import os
import sys
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, OperationFailure

# Sử dụng biến môi trường từ env.py (hoặc .env nếu bạn đã chuyển đổi)
try:
    # Thử import các biến đã được set bởi env.py nếu nó chạy trước
    MONGO_URI = os.environ.get("MONGO_URI")
    MONGODB_NAME = os.environ.get("MONGODB_NAME", "MyCookBook") # Lấy tên DB, mặc định là MyCookBook
    if not MONGO_URI:
        # Nếu chưa có, import trực tiếp từ env.py
        if os.path.exists("env.py"):
            import env # Thực thi env.py để set biến môi trường
            MONGO_URI = os.environ.get("MONGO_URI")
            MONGODB_NAME = os.environ.get("MONGODB_NAME", "MyCookBook")
        else:
             print("LỖI: Không tìm thấy file env.py và biến môi trường MONGO_URI chưa được đặt.")
             sys.exit(1)

    if not MONGO_URI:
        print("LỖI: Biến môi trường MONGO_URI không được đặt trong env.py hoặc môi trường.")
        sys.exit(1)

except ImportError:
    print("LỖI: Không thể import env.py. Đảm bảo file tồn tại và đúng cấu trúc.")
    sys.exit(1)
except Exception as e:
     print(f"Lỗi khi đọc cấu hình: {e}")
     sys.exit(1)


def update_existing_users():
    """Kết nối tới MongoDB và cập nhật schema cho các user hiện có."""
    print(f"Đang kết nối tới MongoDB Atlas...")
    try:
        client = MongoClient(MONGO_URI)
        # Kiểm tra kết nối
        client.admin.command('ping')
        print("Kết nối MongoDB thành công!")
    except ConnectionFailure as e:
        print(f"LỖI: Không thể kết nối tới MongoDB. Kiểm tra MONGO_URI và mạng.")
        print(f"Chi tiết lỗi: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"LỖI kết nối không xác định: {e}")
        sys.exit(1)

    try:
        db = client[MONGODB_NAME]
        users_collection = db["users"]
        print(f"Sử dụng database: '{MONGODB_NAME}', collection: 'users'")

        # --- Cập nhật trường 'role' ---
        print("\nCập nhật trường 'role' cho các user chưa có...")
        # Chỉ cập nhật những document chưa có trường 'role'
        filter_role = {'role': {'$exists': False}}
        update_role = {'$set': {'role': 'user'}}
        result_role = users_collection.update_many(filter_role, update_role)

        print(f"- Tìm thấy: {result_role.matched_count} user chưa có trường 'role'.")
        print(f"- Đã cập nhật: {result_role.modified_count} user (đặt role='user').")
        if result_role.matched_count > result_role.modified_count:
             print("  (Lưu ý: Một số user có thể đã được cập nhật trước đó hoặc có lỗi không mong muốn)")

        # --- Cập nhật trường 'password_set' ---
        print("\nCập nhật trường 'password_set' cho các user chưa có...")
        # Chỉ cập nhật những document chưa có trường 'password_set'
        filter_pw_set = {'password_set': {'$exists': False}}
        update_pw_set = {'$set': {'password_set': True}}
        result_pw_set = users_collection.update_many(filter_pw_set, update_pw_set)

        print(f"- Tìm thấy: {result_pw_set.matched_count} user chưa có trường 'password_set'.")
        print(f"- Đã cập nhật: {result_pw_set.modified_count} user (đặt password_set=True).")
        if result_pw_set.matched_count > result_pw_set.modified_count:
             print("  (Lưu ý: Một số user có thể đã được cập nhật trước đó hoặc có lỗi không mong muốn)")

    except OperationFailure as e:
        print(f"LỖI thao tác MongoDB: {e}")
    except Exception as e:
        print(f"LỖI không xác định trong quá trình cập nhật: {e}")
    finally:
        print("\nĐóng kết nối MongoDB.")
        client.close()

if __name__ == "__main__":
    print("--- Bắt đầu Script Cập nhật Schema User ---")
    update_existing_users()
    print("--- Kết thúc Script ---")