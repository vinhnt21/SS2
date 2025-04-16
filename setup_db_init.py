import os
import sys
from pymongo import MongoClient, errors
from werkzeug.security import generate_password_hash
import env # Import to load environment variables from env.py

# --- Configuration ---
MONGO_URI = os.environ.get("MONGO_URI")
DB_NAME = os.environ.get("MONGODB_NAME", "MyCookBook") # Default to MyCookBook if not set

# --- Check Configuration ---
if not MONGO_URI:
    print("ERROR: MONGO_URI environment variable not set.")
    print("Please ensure MONGO_URI is defined in your env.py file or environment.")
    sys.exit(1)
if not DB_NAME:
     print("ERROR: MONGODB_NAME environment variable not set.")
     print("Please ensure MONGODB_NAME is defined in your env.py file or environment.")
     sys.exit(1)


# --- Initial Data for Dropdowns ---
INITIAL_DATA = {
    "cuisines": [
        {"cuisine_type": "Italian"}, {"cuisine_type": "Mexican"},
        {"cuisine_type": "Vietnamese"}, {"cuisine_type": "Thai"},
        {"cuisine_type": "Indian"}, {"cuisine_type": "French"},
        {"cuisine_type": "American"}, {"cuisine_type": "Chinese"},
        {"cuisine_type": "Japanese"}, {"cuisine_type": "Spanish"},
        {"cuisine_type": "Greek"}, {"cuisine_type": "Other"},
    ],
    "meals": [
        {"meal_type": "Breakfast"}, {"meal_type": "Lunch"},
        {"meal_type": "Dinner"}, {"meal_type": "Dessert"},
        {"meal_type": "Snack"}, {"meal_type": "Appetizer"},
        {"meal_type": "Side Dish"}, {"meal_type": "Soup"},
    ],
    "diets": [
        {"diet_type": "Vegetarian"}, {"diet_type": "Vegan"},
        {"diet_type": "Gluten-Free"}, {"diet_type": "Keto"},
        {"diet_type": "Paleo"}, {"diet_type": "Pescatarian"},
        {"diet_type": "Low-Carb"}, {"diet_type": "Dairy-Free"},
        {"diet_type": "None"},
    ]
}

# --- Collections to Ensure Exist ---
COLLECTIONS = ["users", "recipes", "cuisines", "diets", "meals"]

# --- Optional Default Admin User ---
CREATE_ADMIN = True # Set to False to skip admin creation
ADMIN_USERNAME = "admin"
ADMIN_EMAIL = "admin@example.com" # Change this email
ADMIN_PASSWORD = "password" # !!! CHANGE THIS IMMEDIATELY AFTER RUNNING !!!

def initialize_database():
    """Connects to MongoDB, optionally drops DB, creates collections,
       populates dropdown data, and optionally creates a default admin."""

    print(f"--- Starting Database Initialization for '{DB_NAME}' ---")

    try:
        print(f"Connecting to MongoDB at: {MONGO_URI.split('@')[-1].split('/')[0]}...") # Mask credentials in URI printout
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=10000) # Increased timeout
        # The ismaster command is cheap and does not require auth.
        client.admin.command('ismaster')
        print("MongoDB connection successful!")
        db = client[DB_NAME]
    except errors.ConnectionFailure as e:
        print("\nERROR: MongoDB Connection Failed.")
        print("Details:", e)
        print("\nPlease check:")
        print("1. Your MONGO_URI in env.py is correct.")
        print("2. MongoDB Atlas IP Whitelist includes your current IP address.")
        print("3. Your internet connection is stable.")
        sys.exit(1)
    except Exception as e:
         print(f"\nERROR: An unexpected error occurred during connection: {e}")
         sys.exit(1)

    # --- Optional: Drop Database ---
    # Uncomment the following lines ONLY if you want to completely reset the database.
    # WARNING: This will permanently delete all data in the database!
    # confirm_drop = input(f"WARNING: Are you sure you want to DROP the database '{DB_NAME}'? (yes/no): ")
    # if confirm_drop.lower() == 'yes':
    #     print(f"Dropping database '{DB_NAME}'...")
    #     client.drop_database(DB_NAME)
    #     print(f"Database '{DB_NAME}' dropped.")
    #     db = client[DB_NAME] # Re-reference the database after dropping
    # else:
    #     print("Database drop cancelled.")

    # --- Ensure Collections Exist ---
    print("\nEnsuring collections exist...")
    existing_collections = db.list_collection_names()
    for coll_name in COLLECTIONS:
        if coll_name not in existing_collections:
            try:
                db.create_collection(coll_name)
                print(f"- Created collection: '{coll_name}'")
            except errors.CollectionInvalid:
                 print(f"- Collection '{coll_name}' already exists (or concurrent creation).")
            except Exception as e:
                 print(f"ERROR: Failed to create collection '{coll_name}': {e}")
        else:
            print(f"- Collection '{coll_name}' already exists.")

    # --- Populate Dropdown Collections ---
    print("\nPopulating dropdown collections (cuisines, meals, diets)...")
    for coll_name, data_list in INITIAL_DATA.items():
        if coll_name in db.list_collection_names():
            collection = db[coll_name]
            key_field = list(data_list[0].keys())[0] # Assumes first key is unique identifier
            upserted_count = 0
            errors_count = 0
            for item in data_list:
                try:
                    result = collection.update_one(
                        {key_field: item[key_field]},
                        {"$set": item},
                        upsert=True
                    )
                    if result.upserted_id:
                        upserted_count += 1
                except Exception as e:
                    print(f"  ERROR adding/updating item in '{coll_name}': {item}. Error: {e}")
                    errors_count += 1
            print(f"- '{coll_name}': Added {upserted_count} new items. {errors_count} errors encountered.")
        else:
            print(f"ERROR: Collection '{coll_name}' not found for data population.")


    # --- Optional: Create Default Admin User ---
    if CREATE_ADMIN:
        print("\nCreating default admin user...")
        users_collection = db["users"]
        # Check if admin username or email already exists
        existing_admin = users_collection.find_one({
            "$or": [{"username": ADMIN_USERNAME}, {"email": ADMIN_EMAIL}]
        })

        if existing_admin:
            print(f"- Admin user '{ADMIN_USERNAME}' or email '{ADMIN_EMAIL}' already exists. Skipping creation.")
        else:
            try:
                hashed_password = generate_password_hash(ADMIN_PASSWORD)
                admin_user = {
                    "username": ADMIN_USERNAME,
                    "email": ADMIN_EMAIL,
                    "password": hashed_password,
                    "role": "admin",
                    "password_set": True,
                    "user_recipes": []
                    # "created_at": datetime.utcnow()
                }
                users_collection.insert_one(admin_user)
                print(f"- Default admin user '{ADMIN_USERNAME}' created successfully.")
                print("\n" + "="*40)
                print("  IMPORTANT SECURITY WARNING!")
                print(f"  Default admin password is '{ADMIN_PASSWORD}'.")
                print("  CHANGE THIS PASSWORD IMMEDIATELY after logging in.")
                print("="*40 + "\n")
            except Exception as e:
                print(f"ERROR: Failed to create default admin user: {e}")

    print("--- Database Initialization Complete ---")
    client.close()
    print("MongoDB connection closed.")

if __name__ == "__main__":
    initialize_database()