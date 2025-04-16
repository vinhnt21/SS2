import os
import sys
from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, OperationFailure
import env

# Tải biến môi trường từ file .env
load_dotenv()

# Lấy chuỗi kết nối MongoDB
MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = "MyCookBook"  # Tên database từ README và connection string

if not MONGO_URI:
    print("LỖI: Biến môi trường MONGO_URI chưa được đặt trong file .env")
    sys.exit(1)

# Danh sách collections cần tạo (dựa trên README)
COLLECTIONS_TO_CREATE = ["cuisines", "meals", "diets", "users", "recipes"]

# Dữ liệu mẫu cho các collection dropdown
INITIAL_DATA = {
    "cuisines": [
        {"cuisine_type": "Italian"},
        {"cuisine_type": "Mexican"},
        {"cuisine_type": "Vietnamese"},
        {"cuisine_type": "Thai"},
        {"cuisine_type": "Indian"},
        {"cuisine_type": "French"},
        {"cuisine_type": "American"},
        {"cuisine_type": "Other"},
    ],
    "meals": [
        {"meal_type": "Breakfast"},
        {"meal_type": "Lunch"},
        {"meal_type": "Dinner"},
        {"meal_type": "Dessert"},
        {"meal_type": "Snack"},
        {"meal_type": "Appetizer"},
    ],
    "diets": [
        {"diet_type": "Vegetarian"},
        {"diet_type": "Vegan"},
        {"diet_type": "Gluten-Free"},
        {"diet_type": "Keto"},
        {"diet_type": "Paleo"},
        {"diet_type": "None"}, # Cho trường hợp không theo chế độ ăn kiêng cụ thể
    ]
}

def setup_database():
    """Kết nối tới MongoDB, tạo collections và thêm dữ liệu mẫu."""
    print(f"Đang kết nối tới MongoDB Atlas...")
    try:
        client = MongoClient(MONGO_URI)
        # Lệnh 'admin' command is cheap and does not require auth.
        client.admin.command('ping')
        print("Kết nối MongoDB thành công!")
    except ConnectionFailure as e:
        print(f"LỖI: Không thể kết nối tới MongoDB. Kiểm tra MONGO_URI và mạng.")
        print(f"Chi tiết lỗi: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"LỖI kết nối không xác định: {e}")
        sys.exit(1)

    db = client[DB_NAME]
    print(f"Sử dụng database: {DB_NAME}")

    existing_collections = db.list_collection_names()
    print(f"Các collection hiện có: {existing_collections}")

    for coll_name in COLLECTIONS_TO_CREATE:
        if coll_name not in existing_collections:
            try:
                db.create_collection(coll_name)
                print(f"- Đã tạo collection: '{coll_name}'")
                existing_collections.append(coll_name) # Cập nhật danh sách để kiểm tra data
            except OperationFailure as e:
                 print(f"LỖI khi tạo collection '{coll_name}': {e}")
                 # Có thể collection đã được tạo ngầm, bỏ qua lỗi này và tiếp tục
            except Exception as e:
                 print(f"LỖI không xác định khi tạo collection '{coll_name}': {e}")
                 continue # Bỏ qua collection này nếu lỗi nghiêm trọng
        else:
             print(f"- Collection '{coll_name}' đã tồn tại.")

        # Thêm dữ liệu mẫu nếu collection nằm trong INITIAL_DATA
        if coll_name in INITIAL_DATA:
            collection = db[coll_name]
            # Sử dụng update_one với upsert=True để tránh trùng lặp nếu chạy lại script
            # Dùng key duy nhất của mỗi document (ví dụ: 'cuisine_type') làm filter
            key_field = list(INITIAL_DATA[coll_name][0].keys())[0] # Lấy tên trường đầu tiên làm key
            added_count = 0
            for item in INITIAL_DATA[coll_name]:
                try:
                    # Cập nhật nếu tìm thấy, chèn nếu không tìm thấy (upsert)
                    result = collection.update_one(
                        {key_field: item[key_field]}, # Filter dựa trên giá trị key
                        {"$set": item},              # Dữ liệu cần chèn/cập nhật
                        upsert=True
                    )
                    if result.upserted_id:
                        added_count += 1
                except Exception as e:
                    print(f"  LỖI khi thêm/cập nhật dữ liệu cho '{coll_name}': {e}")

            if added_count > 0:
                 print(f"  -> Đã thêm {added_count} mục dữ liệu mẫu vào '{coll_name}'.")
            else:
                 print(f"  -> Không có mục dữ liệu mẫu mới nào được thêm vào '{coll_name}' (có thể đã tồn tại).")

    print("\nHoàn tất quá trình setup database!")
    client.close()
    print("Đã đóng kết nối MongoDB.")

if __name__ == "__main__":
    setup_database()