from flask import render_template, url_for, flash, redirect, request, session, g
from authlib.integrations.flask_client import OAuth
from mycookbook import app, mongo, oauth
from werkzeug.security import generate_password_hash, check_password_hash
from mycookbook.forms import RegisterForm, LoginForm, \
    ChangeUsernameForm, ChangePasswordForm, Add_RecipeForm, AdminAddUserForm, AdminEditUserForm
from flask_pymongo import pymongo
from bson.objectid import ObjectId
import math
from functools import wraps
import traceback
# MongoDB Collections variables
users_coll = mongo.db["users"]
recipes_coll = mongo.db["recipes"]
cuisines_coll = mongo.db["cuisines"]
diets_coll = mongo.db["diets"]
meals_coll = mongo.db["meals"]

@app.context_processor
def inject_user_role():
    """Inject current user info into template context."""
    user = None
    is_admin = False
    password_needs_set = False
    if 'username' in session:
        user = getattr(g, '_current_user', None)
        if user is None:
            user = users_coll.find_one({"username": session['username']})
            g._current_user = user # Lưu vào g

        if user:
            is_admin = user.get('role') == 'admin'
            password_needs_set = not user.get('password_set', True) # True nếu chưa set

    return dict(current_user=user, is_admin=is_admin, password_needs_set=password_needs_set)

'''
ADMIN
'''
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Kiểm tra xem user đã đăng nhập chưa
        if 'username' not in session:
            flash("Bạn phải đăng nhập để truy cập trang này.", "warning")
            return redirect(url_for('login'))
        # Lấy thông tin user từ DB
        user = users_coll.find_one({"username": session['username']})
        # Kiểm tra user có tồn tại và có role 'admin' không
        if not user or user.get('role') != 'admin':
            flash("Bạn không có quyền truy cập trang này.", "danger")
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin/users')
@admin_required
def admin_users():
    # Fetch all users except the current admin to prevent self-modification via list
    # Though edit/delete routes have specific checks too
    all_users = list(users_coll.find({'username': {'$ne': session.get('username')}}).sort('username', 1))
    current_admin_user = users_coll.find_one({'username': session.get('username')})
    return render_template('admin_users.html',
                           users=all_users,
                           current_admin_user=current_admin_user, # Pass current admin separately if needed
                           title='Admin - Manage Users')

# --- Admin Add User ---
@app.route('/admin/add_user', methods=['GET', 'POST'])
@admin_required
def admin_add_user():
    form = AdminAddUserForm()
    if form.validate_on_submit():
        users = users_coll
        existing_username = users.find_one({'username': form.username.data})
        existing_email = users.find_one({'email': form.email.data})

        if existing_username:
            flash(f"Username '{form.username.data}' is already taken.", 'danger')
        elif existing_email:
             flash(f"Email '{form.email.data}' is already associated with an account.", 'danger')
        else:
            # Hash the password
            hashed_password = generate_password_hash(form.password.data)
            # Create the new user document
            new_user_data = {
                "username": form.username.data,
                "email": form.email.data,
                "password": hashed_password,
                "role": form.role.data,
                "password_set": True, # Password is set by admin
                "user_recipes": []
                # "created_at": datetime.utcnow()
            }
            users.insert_one(new_user_data)
            flash(f"User '{form.username.data}' added successfully.", 'success')
            return redirect(url_for('admin_users'))

    return render_template('admin_add_user.html', form=form, title='Admin - Add User')


# --- Admin Edit User ---
@app.route('/admin/edit_user/<user_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_user(user_id):
    try:
        oid = ObjectId(user_id)
    except Exception:
        flash("Invalid User ID format.", "danger")
        return redirect(url_for('admin_users'))

    user_to_edit = users_coll.find_one({"_id": oid})

    if not user_to_edit:
        flash("User not found.", "error")
        return redirect(url_for('admin_users'))

    # Prevent admin from editing themselves via this route (extra precaution)
    if user_to_edit['username'] == session.get('username'):
         flash("Admins cannot edit their own profile via this page. Use regular account settings.", "warning")
         return redirect(url_for('admin_users'))

    form = AdminEditUserForm(obj=user_to_edit) # Pre-populate form

    if form.validate_on_submit():
        new_username = form.username.data
        new_email = form.email.data
        new_role = form.role.data

        # Check for username conflict (if changed)
        if new_username != user_to_edit['username']:
            existing_username = users_coll.find_one({'username': new_username, '_id': {'$ne': oid}})
            if existing_username:
                flash(f"Username '{new_username}' is already taken.", 'danger')
                # Re-render form with error
                return render_template('admin_edit_user.html', form=form, user=user_to_edit, title='Admin - Edit User')

        # Check for email conflict (if changed)
        if new_email != user_to_edit.get('email'): # Use .get() for safety if email might be missing
            existing_email = users_coll.find_one({'email': new_email, '_id': {'$ne': oid}})
            if existing_email:
                flash(f"Email '{new_email}' is already associated with another account.", 'danger')
                 # Re-render form with error
                return render_template('admin_edit_user.html', form=form, user=user_to_edit, title='Admin - Edit User')

        # Prevent changing role *to* admin if you want to limit admin creation
        # Or prevent changing role *of* admin if needed (though self-edit is already blocked)
        # if new_role == 'admin' and user_to_edit['role'] != 'admin':
        #    flash("Cannot elevate users to admin via this form.", "warning") # Example restriction
        #    return redirect(url_for('admin_users'))

        # Update user document
        users_coll.update_one({"_id": oid}, {
            "$set": {
                "username": new_username,
                "email": new_email,
                "role": new_role
                # Add other fields if the form included them (e.g., password reset flag)
            }
        })
        flash(f"User '{new_username}' updated successfully.", 'success')
        return redirect(url_for('admin_users'))

    # On GET request or validation failure
    return render_template('admin_edit_user.html', form=form, user=user_to_edit, title='Admin - Edit User')


# --- Admin Delete User (Keep existing, ensure checks are robust) ---
@app.route('/admin/delete_user/<user_id>')
@admin_required
def admin_delete_user(user_id):
    try:
        oid = ObjectId(user_id)
    except Exception:
        flash("Invalid User ID format.", "danger")
        return redirect(url_for('admin_users'))

    user_to_delete = users_coll.find_one({"_id": oid})

    if not user_to_delete:
         flash("User not found!", "error")
         return redirect(url_for('admin_users'))

    # Prevent admin from deleting themselves
    if user_to_delete['username'] == session.get('username'):
         flash("You cannot delete your own admin account.", "warning")
         return redirect(url_for('admin_users'))

    # Optional: Prevent deleting other admins
    # if user_to_delete.get('role') == 'admin':
    #     flash("Cannot delete other admin accounts.", "warning")
    #     return redirect(url_for('admin_users'))

    # Delete associated recipes (decision from original code/request)
    # Consider consequences: Keep recipes but orphan them? Assign to admin?
    all_user_recipes_ids = user_to_delete.get("user_recipes", [])
    if all_user_recipes_ids:
         try:
             # Convert potential string IDs to ObjectIds if necessary
             object_ids = [ObjectId(r_id) for r_id in all_user_recipes_ids]
             delete_result = recipes_coll.delete_many({"_id": {"$in": object_ids}})
             print(f"DEBUG: Deleted {delete_result.deleted_count} recipes for user {user_to_delete['username']}")
         except Exception as e:
              app.logger.error(f"Error deleting recipes for user {user_id}: {e}")
              flash(f"Could not delete recipes associated with user {user_to_delete['username']}. Please check logs.", "warning")
              # Decide whether to proceed with user deletion or stop

    # Delete the user
    users_coll.delete_one({"_id": oid})
    flash(f"User '{user_to_delete['username']}' and their recipes have been deleted.", "success")
    return redirect(url_for('admin_users'))




# --- Admin List All Recipes ---
@app.route('/admin/recipes')
@admin_required
def admin_recipes():
    '''
    ADMIN READ.
    Displays all recipes from the database for admin management with pagination.
    '''
    limit_per_page = 8 # Hoặc số lượng bạn muốn
    current_page = int(request.args.get('current_page', 1))
    recipes_coll = mongo.db.recipes
    users_coll = mongo.db.users # Cần để lấy tên tác giả

    number_of_all_rec = recipes_coll.count_documents({})
    pages = range(1, int(math.ceil(number_of_all_rec / limit_per_page)) + 1)

    # Lấy công thức với thông tin tác giả
    pipeline = [
        {
            '$sort': {'_id': pymongo.ASCENDING} # Hoặc sắp xếp theo tiêu chí khác
        },
        {
            '$skip': (current_page - 1) * limit_per_page
        },
        {
            '$limit': limit_per_page
        },
        {
            '$lookup': {
                'from': 'users',
                'localField': 'author',
                'foreignField': '_id',
                'as': 'author_info'
            }
        },
        {
             # Giải nén mảng author_info (chỉ có 1 phần tử)
            '$unwind': {
                'path': '$author_info',
                 # Giữ lại recipe ngay cả khi không tìm thấy user (an toàn hơn)
                'preserveNullAndEmptyArrays': True
            }
        },
        {
            '$addFields': {
                 # Thêm trường author_username, xử lý trường hợp user bị xóa
                'author_username': '$author_info.username'
            }
        }
    ]

    recipes_list = list(recipes_coll.aggregate(pipeline))

    return render_template("admin_recipes.html",
                           recipes=recipes_list,
                           title='Admin - Manage Recipes',
                           current_page=current_page,
                           pages=pages,
                           number_of_all_rec=number_of_all_rec)


# --- Admin Add Recipe (Show Form) ---
@app.route('/admin/add_recipe', methods=['GET'])
@admin_required
def admin_add_recipe_form():
    '''
    ADMIN CREATE (Form).
    Displays the form for admin to add a new recipe.
    '''
    form = Add_RecipeForm()
    # Lấy dữ liệu cho dropdowns giống như route add_recipe của user
    diet_types = mongo.db.diets.find()
    meal_types = mongo.db.meals.find()
    cuisine_types = mongo.db.cuisines.find()
    return render_template("admin_add_recipe.html", # Template mới
                           form=form,
                           diet_types=diet_types,
                           cuisine_types=cuisine_types,
                           meal_types=meal_types,
                           title='Admin - Add New Recipe')

# --- Admin Insert Recipe (Handle Submission) ---
@app.route("/admin/insert_recipe", methods=['POST'])
@admin_required
def admin_insert_recipe():
    '''
    ADMIN CREATE (Action).
    Inserts the new recipe added by admin into the DB.
    The author will be the logged-in admin.
    '''
    recipes_coll = mongo.db.recipes
    users_coll = mongo.db.users
    form = Add_RecipeForm() # Dùng để validate nếu cần, nhưng ở đây lấy trực tiếp từ request.form

    if request.method == 'POST':
        # Lấy thông tin admin đang đăng nhập
        admin_user = users_coll.find_one({"username": session["username"]})
        if not admin_user:
            flash("Admin user not found.", "error")
            return redirect(url_for('admin_recipes'))
        admin_author_id = admin_user["_id"]

        # Tách ingredients và directions
        ingredients = request.form.get("ingredients", "").splitlines()
        directions = request.form.get("recipe_directions", "").splitlines()

        # Tạo document công thức mới
        new_recipe_data = {
            "recipe_name": request.form.get("recipe_name", "").strip(),
            "description": request.form.get("recipe_description", ""),
            "cuisine_type": request.form.get("cuisine_type"),
            "meal_type": request.form.get("meal_type"),
            "diet_type": request.form.get("diet_type"),
            "cooking_time": request.form.get("cooking_time"),
            "servings": request.form.get("servings"),
            "ingredients": [ing for ing in ingredients if ing.strip()], # Loại bỏ dòng trống
            "directions": [direc for direc in directions if direc.strip()], # Loại bỏ dòng trống
            'author': admin_author_id, # Gán admin là tác giả
            "image": request.form.get("image")
        }

        try:
            insert_result = recipes_coll.insert_one(new_recipe_data)
            # Cập nhật danh sách công thức của admin
            users_coll.update_one(
                {"_id": admin_author_id},
                {"$push": {"user_recipes": insert_result.inserted_id}}
            )
            flash('Recipe added successfully by admin.', 'success')
            # Chuyển hướng đến trang chi tiết công thức vừa tạo hoặc danh sách admin
            return redirect(url_for("single_recipe_details", recipe_id=insert_result.inserted_id))
            # Hoặc: return redirect(url_for('admin_recipes'))
        except Exception as e:
             flash(f"Error adding recipe: {e}", 'danger')
             # Có thể render lại form với lỗi nếu cần
             return redirect(url_for('admin_add_recipe_form'))

    # Nếu không phải POST (dù route chỉ định POST, đề phòng)
    return redirect(url_for('admin_add_recipe_form'))


# --- Admin Edit Recipe (Show Form) ---
@app.route("/admin/edit_recipe/<recipe_id>", methods=['GET'])
@admin_required
def admin_edit_recipe_form(recipe_id):
    '''
    ADMIN UPDATE (Form).
    Displays the form for admin to edit any recipe, pre-populated.
    '''
    try:
        oid = ObjectId(recipe_id)
    except Exception:
        flash("Invalid Recipe ID format.", "danger")
        return redirect(url_for('admin_recipes'))

    recipes_coll = mongo.db.recipes
    selected_recipe = recipes_coll.find_one({"_id": oid})

    if not selected_recipe:
        flash("Recipe not found.", "error")
        return redirect(url_for('admin_recipes'))

    form = Add_RecipeForm() # Form này sẽ được dùng để render cấu trúc, dữ liệu lấy từ selected_recipe

    # Lấy dữ liệu cho dropdowns
    diet_types = mongo.db.diets.find()
    meal_types = mongo.db.meals.find()
    cuisine_types = mongo.db.cuisines.find()

    return render_template('admin_edit_recipe.html', # Template mới
                           selected_recipe=selected_recipe,
                           form=form, # Truyền form để render cấu trúc nếu cần
                           cuisine_types=cuisine_types,
                           diet_types=diet_types,
                           meal_types=meal_types,
                           title='Admin - Edit Recipe')

# --- Admin Update Recipe (Handle Submission) ---
@app.route("/admin/update_recipe/<recipe_id>", methods=["POST"])
@admin_required
def admin_update_recipe(recipe_id):
    '''
    ADMIN UPDATE (Action).
    Updates the selected recipe in the database based on admin's submission.
    Does NOT change the original author.
    '''
    try:
        oid = ObjectId(recipe_id)
    except Exception:
        flash("Invalid Recipe ID format.", "danger")
        return redirect(url_for('admin_recipes'))

    recipes_coll = mongo.db.recipes
    selected_recipe = recipes_coll.find_one({"_id": oid})

    if not selected_recipe:
         flash("Recipe not found!", "error")
         return redirect(url_for('admin_recipes'))

    # Lấy ID tác giả gốc (KHÔNG THAY ĐỔI)
    original_author_id = selected_recipe.get("author")

    # Tách ingredients và directions
    ingredients = request.form.get("ingredients", "").splitlines()
    directions = request.form.get("recipe_directions", "").splitlines() # Sửa key name nếu cần khớp với form

    if request.method == "POST":
        update_data = {
            "$set": {
                "recipe_name": request.form.get("recipe_name", "").strip(),
                "description": request.form.get("recipe_description", ""),
                "cuisine_type": request.form.get("cuisine_type"),
                "meal_type": request.form.get("meal_type"),
                "diet_type": request.form.get("diet_type"),
                "cooking_time": request.form.get("cooking_time"),
                "servings": request.form.get("servings"),
                "ingredients": [ing for ing in ingredients if ing.strip()],
                "directions": [direc for direc in directions if direc.strip()],
                'author': original_author_id, # Giữ nguyên tác giả gốc
                "image": request.form.get("image") # Sửa key name nếu cần khớp với form edit
                # Lưu ý: Key name cho image trong form edit_recipe.html là "recipe_image"
                # "image": request.form.get("recipe_image") # <- Sử dụng key này nếu form là admin_edit_recipe.html copy từ edit_recipe.html
            }
        }

        try:
             recipes_coll.update_one({"_id": oid}, update_data)
             flash('Recipe updated successfully by admin.', 'success')
             return redirect(url_for("single_recipe_details", recipe_id=recipe_id))
             # Hoặc: return redirect(url_for('admin_recipes'))
        except Exception as e:
             flash(f"Error updating recipe: {e}", 'danger')
              # Render lại form edit với lỗi
             # Cần lấy lại dropdown data nếu render lại template
             diet_types = mongo.db.diets.find()
             meal_types = mongo.db.meals.find()
             cuisine_types = mongo.db.cuisines.find()
             form = Add_RecipeForm() # Có thể cần truyền lại request.form vào form để giữ giá trị nhập
             return render_template('admin_edit_recipe.html',
                                    selected_recipe=request.form, # Truyền dữ liệu form lỗi
                                    recipe_id=recipe_id, # Cần ID để form action đúng
                                    form=form,
                                    cuisine_types=cuisine_types,
                                    diet_types=diet_types,
                                    meal_types=meal_types,
                                    title='Admin - Edit Recipe')

    # Nếu không phải POST
    return redirect(url_for('admin_edit_recipe_form', recipe_id=recipe_id))


# --- Admin Delete Recipe ---
@app.route("/admin/delete_recipe/<recipe_id>") # Thường dùng GET cho link xóa với confirm JS
@admin_required
def admin_delete_recipe(recipe_id):
    '''
    ADMIN DELETE.
    Removes the selected recipe from the database.
    Also removes the recipe ID from the original author's user_recipes list.
    '''
    try:
        oid = ObjectId(recipe_id)
    except Exception:
        flash("Invalid Recipe ID format.", "danger")
        return redirect(url_for('admin_recipes'))

    recipes_coll = mongo.db.recipes
    users_coll = mongo.db.users

    # Tìm công thức để lấy ID tác giả gốc
    recipe_to_delete = recipes_coll.find_one({"_id": oid})

    if not recipe_to_delete:
        flash("Recipe not found!", "error")
        return redirect(url_for('admin_recipes'))

    original_author_id = recipe_to_delete.get("author")

    try:
        # Xóa công thức khỏi collection 'recipes'
        delete_result = recipes_coll.delete_one({"_id": oid})

        if delete_result.deleted_count == 1:
            # Nếu xóa thành công, xóa ID công thức khỏi danh sách của tác giả gốc
            if original_author_id:
                 # Đảm bảo original_author_id là ObjectId nếu nó chưa phải
                 if not isinstance(original_author_id, ObjectId):
                     try:
                         original_author_id = ObjectId(original_author_id)
                     except Exception:
                          flash("Invalid author ID format associated with the recipe. Recipe deleted, but couldn't update author list.", "warning")
                          original_author_id = None # Đặt lại để bỏ qua bước update

                 if original_author_id:
                     users_coll.update_one(
                         {"_id": original_author_id},
                         {"$pull": {"user_recipes": oid}}
                     )
            flash('Recipe deleted successfully by admin.', 'success')
        else:
            flash('Recipe could not be deleted.', 'warning')

    except Exception as e:
         flash(f"Error deleting recipe: {e}", 'danger')

    return redirect(url_for("admin_recipes"))





'''
GOOGLE AUTHENTICATION
'''

@app.route('/google/login')
def google_login():
    """Chuyển hướng người dùng đến trang đăng nhập Google."""
    redirect_uri = url_for('google_callback', _external=True)
    print(f"DEBUG: Redirect URI for Google Auth: {redirect_uri}")
    return oauth.google.authorize_redirect(redirect_uri)

@app.route('/google/callback')
def google_callback():
    """Xử lý callback từ Google sau khi người dùng xác thực."""
    try:
        # 1. Lấy access token
        token = oauth.google.authorize_access_token()
        if not token:
             flash("Google authentication failed: Could not authorize access token.", "danger")
             return redirect(url_for('login'))

        # 2. Dùng access token để lấy thông tin user
        # --- Hoàn nguyên về cách lấy user info cũ ---
        # Xác định URL UserInfo endpoint một cách rõ ràng
        # Thông thường lấy từ cấu hình nhưng phiên bản cũ có thể cần khai báo trực tiếp
        # Dựa trên cấu hình trong __init__.py của bạn [cite: uploaded:MyCookBook_v2/mycookbook/__init__.py]:
        userinfo_endpoint = 'https://openidconnect.googleapis.com/v1/userinfo'
        print(f"DEBUG: Attempting to fetch user info from: {userinfo_endpoint}")

        # Thực hiện lệnh gọi GET với URL đầy đủ
        resp = oauth.google.get(userinfo_endpoint)
        print(f"DEBUG: User info response status: {resp.status_code}") # Debug status code

        # Kiểm tra lỗi HTTP
        resp.raise_for_status()
        user_info = resp.json() # Lấy dữ liệu JSON

        google_email = user_info.get('email')
        google_name = user_info.get('name')

        if not google_email:
             flash("Could not retrieve email address from Google.", "danger")
             return redirect(url_for('login'))

        # 3. --- LOGIC MỚI: Kiểm tra xem email này đã tồn tại trong DB chưa ---
        existing_user = users_coll.find_one({'email': google_email})

        if existing_user:
            # User found by email - Log them in
            session['username'] = existing_user['username'] # Log in với username hiện tại
            g._current_user = existing_user
            flash(f"Welcome back, {existing_user['username']}!", "success")
            # Optional: Cập nhật last login time...

            password_needs_set = not existing_user.get('password_set', True)
            if password_needs_set:
                flash("Please set a password for your account.", "info")
                return redirect(url_for('change_password', username=session['username']))
            return redirect(url_for('home'))
        else:
            # --- User NOT found by email - Create NEW user ---
            initial_username = google_email
            username_conflict = users_coll.find_one({'username': initial_username})

            if username_conflict:
                 # Xử lý xung đột username (logic giữ nguyên từ phản hồi trước)
                 if google_name:
                     potential_username = google_name.replace(" ", "").lower()
                     if not users_coll.find_one({'username': potential_username}):
                         initial_username = potential_username
                     else:
                         initial_username = google_email.split('@')[0] + "_" + os.urandom(3).hex()
                 else:
                      initial_username = google_email.split('@')[0] + "_" + os.urandom(3).hex()

                 if users_coll.find_one({'username': initial_username}):
                      flash("Failed to create a unique username. Please try registering manually.", "danger")
                      return redirect(url_for('register'))

            # Tạo user mới
            new_user_data = {
                "username": initial_username,
                "email": google_email, # Lưu email
                "password": None,      # Chưa có mật khẩu
                "user_recipes": [],
                "role": "user",
                "password_set": False # Cần đặt mật khẩu
                # "created_at": datetime.utcnow()
            }
            result = users_coll.insert_one(new_user_data)
            new_user = users_coll.find_one({"_id": result.inserted_id})

            session['username'] = new_user['username'] # Đăng nhập với username mới
            g._current_user = new_user
            flash(f"Google sign-in successful! Welcome, {new_user['username']}. Please set a password for your account.", "success")
            return redirect(url_for('change_password', username=session['username'])) # Chuyển đến trang đặt mật khẩu

    except Exception as e:
        # Log lỗi để debug
        app.logger.error(f"Google Callback Error: {e.__class__.__name__}: {e}")
        traceback.print_exc() # In traceback chi tiết
        flash("An error occurred during Google authentication. Please try logging in again.", "danger")
        return redirect(url_for('login'))

'''
HOME PAGE
'''


@app.route('/')
@app.route("/home")
def home():
    '''
    Main home page.
    Allows users to view 4 random featured recipes
    from the database as clickable cards, located bellow the hero image.
    '''
    # Generate 4 random recipes from the DB
    featured_recipes = ([recipe for recipe in recipes_coll.aggregate
                        ([{"$sample": {"size": 4}}])])
    return render_template('home.html', featured_recipes=featured_recipes,
                           title='Home')


'''
RECIPES ROUTES
'''


# All recipes display
@app.route('/all_recipes')
def all_recipes():
    '''
    READ.
    Displays all the recipes from the database using pagination.
    The limit is set to 8 recipes per page.
    Also displayes the number of all recipes.
    '''
    # CREDITS: the idea of pagination used below is taken and modified
    # from the Shane Muirhead's project
    limit_per_page = 8
    current_page = int(request.args.get('current_page', 1))
    # get total of all the recipes in db
    number_of_all_rec = recipes_coll.count()
    pages = range(1, int(math.ceil(number_of_all_rec / limit_per_page)) + 1)
    recipes = recipes_coll.find().sort('_id', pymongo.ASCENDING).skip(
        (current_page - 1)*limit_per_page).limit(limit_per_page)

    return render_template("all_recipes.html", recipes=recipes,
                           title='All Recipes', current_page=current_page,
                           pages=pages, number_of_all_rec=number_of_all_rec)


# Single Recipe details display
@app.route('/recipe_details/<recipe_id>')
def single_recipe_details(recipe_id):
    '''
    READ.
    Displays detailed information about a selected recipe.
    If logged id user is an author of the selected recipe,
    there are buttons "edit" and "delete" displayed
    giving the oportunity to manipulate the recipe.
    '''
    # find the selected recipe in DB by its id
    selected_recipe = recipes_coll.find_one({"_id": ObjectId(recipe_id)})
    # Set the author of the recipe
    author = users_coll.find_one(
        {"_id": ObjectId(selected_recipe.get("author"))})["username"]
    return render_template("single_recipe_details.html",
                           selected_recipe=selected_recipe, author=author,
                           title='Recipe Details')


# My recipes
@app.route('/my_recipes/<username>')
def my_recipes(username):
    '''
    READ.
    Displays the recipes created by logged in user in session.
    If user has not created any recipes yet, there's a button "add recipe"
    giving an opportunity to create a new recipe.
    Pagination is in place diplaying 8 recipes per page.
    Also displays the total number of recipes created by the user.
    '''
    my_id = users_coll.find_one({'username': session['username']})['_id']
    my_username = users_coll.find_one({'username': session
                                      ['username']})['username']
    # finds all user's recipes by author id
    my_recipes = recipes_coll.find({'author': my_id})
    # get total number of recipes created by the user
    number_of_my_rec = my_recipes.count()
    # Pagination, displays 8 recipes per page
    # CREDITS: the idea of pagination used below is taken and modified
    # from the Shane Muirhead's project
    limit_per_page = 8
    current_page = int(request.args.get('current_page', 1))
    pages = range(1, int(math.ceil(number_of_my_rec / limit_per_page)) + 1)
    recipes = my_recipes.sort('_id', pymongo.ASCENDING).skip(
        (current_page - 1)*limit_per_page).limit(limit_per_page)

    return render_template("my_recipes.html", my_recipes=my_recipes,
                           username=my_username, recipes=recipes,
                           number_of_my_rec=number_of_my_rec,
                           current_page=current_page, pages=pages,
                           title='My Recipes')


# Add recipe
@app.route('/add_recipe')
def add_recipe():
    '''
    CREATE.
    The function calls Add_RecipeForm class from forms.py
    to diplay the form for adding new recipe,
    fill dropdowns with data from cuisins, diets and meals collections.
    Only logged in users can view and fill the form
    '''
    # prevents guest users from viewing the form
    if 'username' not in session:
        flash('You must be logged in to add a new recipe!')
        return redirect(url_for('home'))
    # form variable to initialise the form
    form = Add_RecipeForm()
    # variables to fill dropdownes with data from collections
    diet_types = diets_coll.find()
    meal_types = meals_coll.find()
    cuisine_types = cuisines_coll.find()
    return render_template("add_recipe.html", diet_types=diet_types,
                           cuisine_types=cuisine_types, meal_types=meal_types,
                           form=form, title='New Recipe')


# Insert recipe
@app.route("/insert_recipe", methods=['GET', 'POST'])
def insert_recipe():
    '''
    CREATE.
    Inserts new created recipe to the "recipes" collection in DB
    after submission the form from the add_recipe page.
    '''

    # split ingredients and directions into lists
    ingredients = request.form.get("ingredients").splitlines()
    directions = request.form.get("recipe_directions").splitlines()
    # identifies the user in session to assign an author for new recipe
    author = users_coll.find_one({"username": session["username"]})["_id"]

    if request.method == 'POST':
        # inser the new recipe after submission the form
        new_recipe = {
            "recipe_name": request.form.get("recipe_name").strip(),
            "description": request.form.get("recipe_description"),
            "cuisine_type": request.form.get("cuisine_type"),
            "meal_type": request.form.get("meal_type"),
            "diet_type": request.form.get("diet_type"),
            "cooking_time": request.form.get("cooking_time"),
            "servings": request.form.get("servings"),
            "ingredients": ingredients,
            "directions": directions,
            'author': author,
            "image": request.form.get("image")
        }
        insert_recipe_intoDB = recipes_coll.insert_one(new_recipe)
        # updates "user recipes" list with recipe_id added in user collection
        users_coll.update_one(
            {"_id": ObjectId(author)},
            {"$push": {"user_recipes": insert_recipe_intoDB.inserted_id}})
        flash('Your recipe  was succsessfully added!')
        return redirect(url_for(
            "single_recipe_details",
            recipe_id=insert_recipe_intoDB.inserted_id))


# Edit Recipe
@app.route("/edit_recipe/<recipe_id>")
def edit_recipe(recipe_id):
    '''
    UPDATE.
    Renders edit_recipe page, provides the user with a form to edit task
    with pre-populated fields.
    '''
    # prevents guest users from viewing the form
    if 'username' not in session:
        flash('You must be logged in to edit a recipe!')
        return redirect(url_for('home'))
    user_in_session = users_coll.find_one({'username': session['username']})
    # get the selected recipe for filling the fields
    selected_recipe = recipes_coll.find_one({"_id": ObjectId(recipe_id)})
    # allows only author of the recipe to edit it;
    # protects againts brute-forcing
    if selected_recipe['author'] == user_in_session['_id'] or user_in_session['role'] == 'admin':
        # variables to fill dropdownes with data from collections
        diet_types = diets_coll.find()
        meal_types = meals_coll.find()
        cuisine_types = cuisines_coll.find()
        return render_template('edit_recipe.html',
                               selected_recipe=selected_recipe,
                               cuisine_types=cuisine_types,
                               diet_types=diet_types,
                               meal_types=meal_types, title='Edit Recipe')
    else:
        flash("You can only edit your own recipes!")
        return redirect(url_for('home'))


# Update Recipe in the Database
@app.route("/update_recipe/<recipe_id>", methods=["POST"])
def update_recipe(recipe_id):
    '''
    UPDATE.
    Updates the selected recipe in the database after submission the form.
    '''
    recipes = recipes_coll

    selected_recipe = recipes_coll.find_one({"_id": ObjectId(recipe_id)})
    # identifies the user in session to assign an author for edited recipe
    author = selected_recipe.get("author")
    # split ingredients and directions into lists
    ingredients = request.form.get("ingredients").splitlines()
    directions = request.form.get("directions").splitlines()
    if request.method == "POST":
        # updates the selected recipe with data gotten from the form
        recipes.update({"_id": ObjectId(recipe_id)}, {
            "recipe_name": request.form.get("recipe_name"),
            "description": request.form.get("recipe_description"),
            "cuisine_type": request.form.get("cuisine_type"),
            "meal_type": request.form.get("meal_type"),
            "cooking_time": request.form.get("cooking_time"),
            "diet_type": request.form.get("diet_type"),
            "servings": request.form.get("servings"),
            "ingredients": ingredients,
            "directions": directions,
            'author': author,
            "image": request.form.get("recipe_image")
        })
        return redirect(url_for("single_recipe_details",
                                recipe_id=recipe_id))


# Delete Recipe
@app.route("/delete_recipe/<recipe_id>")
def delete_recipe(recipe_id):
    '''
    DELETE.
    Removes the selected recipe from the database.
    Only the author of the recipe can delete the recipe.
    '''
    # prevents guest users from viewing the modal
    if 'username' not in session:
        flash('You must be logged in to delete a recipe!')
        return redirect(url_for('home'))
    user_in_session = users_coll.find_one({'username': session['username']})
    # get the selected recipe for filling the fields
    selected_recipe = recipes_coll.find_one({"_id": ObjectId(recipe_id)})
    # allows only author of the recipe to delete it;
    # protects againts brute-forcing
    if selected_recipe['author'] == user_in_session['_id']:
        recipes_coll.remove({"_id": ObjectId(recipe_id)})
        # find the author of the selected recipe
        author = users_coll.find_one({'username': session['username']})['_id']

        users_coll.update_one({"_id": ObjectId(author)},
                              {"$pull": {"user_recipes": ObjectId(recipe_id)}})
        flash('Your recipe has been deleted.')
        return redirect(url_for("home"))
    else:
        flash("You can only delete your own recipes!")
        return redirect(url_for('home'))


'''
USER ROUTES
'''


# Login
@app.route("/login",  methods=['GET', 'POST'])
def login():
    '''
    The login function calls LoginForm class from forms.py,
    It checks if the entered username and passwords are valid
    and then add user to session.
    '''
    # Check if the user is already logged in
    if 'username' in session:
        flash('You are already logged in!')
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        # Variable for users collection
        users = users_coll
        registered_user = users.find_one({'username':
                                          request.form['username']})

        if registered_user:
            # Check if password in the form is equal to the password in the DB
            if check_password_hash(registered_user['password'],
                                   request.form['password']):
                # Add user to session if passwords match
                session['username'] = request.form['username']
                flash('You have been successfully logged in!')
                return redirect(url_for('home'))
            else:
                # if user entered incorrect password
                flash("Incorrect username or password. Please try again")
                return redirect(url_for('login'))
        else:
            # if user entered incorrect username
            flash("Username does not exist! Please try again")
            return redirect(url_for('login'))
    return render_template('login.html',  form=form, title='Login')


# Register
@app.route("/register", methods=['GET', 'POST'])
def register():
    '''
    CREATE.
    Creates a new account; it calls the RegisterForm class from forms.py.
    Checks if the username or email is not already existing in the database,
    hashes the entered password and adds a new user to session.
    Requires email field now.
    '''
    if 'username' in session:
        flash('You are already registered and logged in!', 'info')
        return redirect(url_for('home'))

    # --- NOTE: RegisterForm needs an email field added ---
    # --- Go back to forms.py and add it ---
    form = RegisterForm() # Assuming RegisterForm now includes an email field

    if form.validate_on_submit():
        users = users_coll
        existing_username = users.find_one({'username': form.username.data})
        # --- Check for existing email ---
        existing_email = users.find_one({'email': form.email.data}) # Assuming form has email.data

        if existing_username:
            flash("Sorry, this username is already taken!", 'danger')
            return redirect(url_for('register'))
        # --- Check email conflict ---
        if existing_email:
            flash("This email address is already associated with an account.", 'danger')
            return redirect(url_for('register'))

        # If username and email are unique, proceed
        hashed_password = generate_password_hash(form.password.data)
        new_user = {
            "username": form.username.data,
            "email": form.email.data, # Store email
            "password": hashed_password,
            "user_recipes": [],
            "role": "user",
            "password_set": True # Password is set during registration
            # "created_at": datetime.utcnow()
        }
        users.insert_one(new_user)
        # add new user to the session
        session["username"] = form.username.data
        g._current_user = new_user # Set g object
        flash('Your account has been successfully created.', 'success')
        return redirect(url_for('home'))

    return render_template('register.html', form=form,  title='Register')

# Logout
@app.route("/logout")
def logout():
    '''
    Logs user out and redirects to home
    '''
    session.pop("username",  None)
    return redirect(url_for("home"))


# Account Settings
@app.route("/account_settings/<username>")
def account_settings(username):
    '''
    Account settings page - displays username,
    buttons for change_username, change_password
    and delete_account pages.
    '''
    # prevents guest users from viewing the page
    if 'username' not in session:
        flash('You must be logged in to view that page!')
    username = users_coll.find_one({'username':
                                    session['username']})['username']
    return render_template('account_settings.html',
                           username=username, title='Account Settings')


# Change username
@app.route("/change_username/<username>", methods=['GET', 'POST'])
def change_username(username):
    '''
    UPDATE.
    Allows user to change the current username.
    It calls the ChangeUsernameForm class from forms.py.
    Checks if the new username is unique and not exist in database,
    then updates the username, clears the session and redirects user to login page.
    Email remains unchanged.
    '''
    if 'username' not in session or session['username'] != username:
        flash('You must be logged in and can only change your own username!', 'warning')
        return redirect(url_for('login'))

    users = users_coll
    user = users.find_one({'username': session['username']})
    if not user:
        flash('User not found.', 'error')
        session.pop("username", None)
        return redirect(url_for('login'))

    form = ChangeUsernameForm()
    if form.validate_on_submit():
        new_username = form.new_username.data
        # Check if the new username is the same as the old one
        if new_username == username:
             flash('New username cannot be the same as the current username.', 'warning')
             return redirect(url_for('change_username', username=username))

        # Check if the new username is already taken by someone else
        existing_user = users.find_one({'username': new_username})
        if existing_user:
            flash('Sorry, that username is already taken. Try another one.', 'danger')
            return redirect(url_for('change_username', username=username))
        else:
            # Update the username in the database
            users.update_one(
                {"_id": user['_id']},
                {"$set": {"username": new_username}})

            # Clear the session and redirect to login page forcing re-login
            flash("Your username was updated successfully. Please log in with your new username.", 'success')
            session.pop("username", None)
            g.pop('_current_user', None) # Clear g object too
            return redirect(url_for("login"))

    # Pass current username for display
    return render_template('change_username.html',
                           username=username, # Pass the actual current username
                           form=form, title='Change Username')

# Change password
@app.route("/change_password/<username>", methods=['GET', 'POST'])
def change_password(username):
    '''
    UPDATE.
    Allows user to change the current password or set it for the first time
    if logged in via Google initially.
    It calls the ChangePasswordForm class from forms.py.
    Checks if the current password is correct (if password was already set),
    validates new password. Then if new password matches confirm password field,
    insert it to the database and set password_set to True.
    '''
    # Prevents guest users from viewing the form
    if 'username' not in session or session['username'] != username:
        flash('You must be logged in and can only change your own password!', 'warning')
        return redirect(url_for('login'))

    users = mongo.db.users
    user = users.find_one({'username': session['username']})

    if not user:
        flash('User not found.', 'error')
        session.pop("username", None)
        return redirect(url_for('login'))

    # Check if the user needs to set the password for the first time
    password_needs_set = not user.get('password_set', True)

    form = ChangePasswordForm()

    # Customize form based on whether the password needs to be set
    if password_needs_set:
        # If setting password for the first time, remove the old_password field's label/requirement visually
        # (The validator is already Optional, but we adjust the template experience)
        # We can pass a flag to the template or adjust the form field here if needed
        # For simplicity, we rely on the logic below to bypass the check.
        # No change needed to the form object itself here, logic handles the check.
        pass # Placeholder for potential future form adjustments if needed
    else:
        # If password is set, old_password is required logically
        # Ensure the Optional validator doesn't bypass our check below
        pass

    if form.validate_on_submit():
        new_password = form.new_password.data
        old_password = form.old_password.data # Get data even if optional

        # If password was already set, verify the old password
        if not password_needs_set:
            if not old_password:
                 flash('Current password is required.', 'danger')
                 # Pass the flag to the template
                 return render_template('change_password.html', username=username, form=form, title='Change Password', password_needs_set=password_needs_set)
            if not user.get('password') or not check_password_hash(user['password'], old_password):
                flash('Incorrect current password! Please try again', 'danger')
                # Pass the flag to the template
                return render_template('change_password.html', username=username, form=form, title='Change Password', password_needs_set=password_needs_set)

        # If validation passes (including old password check if applicable), update the password
        hashed_new_password = generate_password_hash(new_password)
        users.update_one({'_id': user['_id']},
                         {'$set': {
                             'password': hashed_new_password,
                             'password_set': True # Ensure this is set to True
                         }})
        flash("Success! Your password was updated.", 'success')
        return redirect(url_for('account_settings', username=session['username']))

    # Pass the flag to the template for conditional rendering
    return render_template('change_password.html', username=username, form=form, title='Change Password', password_needs_set=password_needs_set)

# Delete Account
@app.route("/delete_account/<username>", methods=['GET', 'POST'])
def delete_account(username):
    '''
    DELETE.
    Remove user's account from the database as well as all recipes
    created by this user. Before deletion of the account, user is asked
    to confirm it by entering password.
    '''
    # prevents guest users from viewing the form
    if 'username' not in session:
        flash('You must be logged in to delete an account!')
    user = users_coll.find_one({"username": username})
    # checks if password matches existing password in database
    if check_password_hash(user["password"],
                           request.form.get("confirm_password_to_delete")):
        # Removes all user's recipes from the Database
        all_user_recipes = user.get("user_recipes")
        for recipe in all_user_recipes:
            recipes_coll.remove({"_id": recipe})
        # remove user from database,clear session and redirect to the home page
        flash("Your account has been deleted.")
        session.pop("username", None)
        users_coll.remove({"_id": user.get("_id")})
        return redirect(url_for("home"))
    else:
        flash("Password is incorrect! Please try again")
        return redirect(url_for("account_settings", username=username))


'''
ERROR HANDLERS
'''

@app.errorhandler(404)
def error_404(error):
    '''
    Handles 404 error (page not found)
    '''
    return render_template('errors/404.html', error=True,
                           title="Page not found"), 404


@app.errorhandler(500)
def error_500(error):
    '''
    Handles 500 error (internal server error)
    '''
    return render_template('errors/500.html', error=True,
                           title="Internal Server Error"), 500


@app.route("/search")
def search():
    """
    A function that finds recipes on query
    The query is the user's input
    Recipes are a list of user queries
    Render user's list recipes on search.html
    """

    limit_per_page = 8
    current_page = int(request.args.get('current_page', 1))

    query = request.args.get('query')

    #  create the index
    recipes_coll.create_index( [("$**", 'text')] )

    #  Search results
    results = \
        recipes_coll.find({'$text': {'$search': str(query)}},
                          {'score': {'$meta': 'textScore'}}).sort('_id'
            , pymongo.ASCENDING).skip((current_page - 1)
            * limit_per_page).limit(limit_per_page)

    # Pagination
    number_of_recipes_found = recipes_coll.find({'$text': {'$search': str(query)}}).count()
    
    results_pages = range(1, int(math.ceil(number_of_recipes_found / limit_per_page)) + 1)
    total_pages = int(math.ceil(number_of_recipes_found / limit_per_page))

    return render_template("search.html",
                            title='Search',
                            limit_per_page=limit_per_page,
                            number_of_recipes_found = number_of_recipes_found,
                            current_page=current_page,
                            query=query,
                            results=results,
                            results_pages=results_pages,
                            total_pages=total_pages)
