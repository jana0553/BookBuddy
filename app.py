from flask import Flask, jsonify, request, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from dotenv import load_dotenv
import requests
from sqlalchemy import or_
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime, timedelta

# Load environment variables
load_dotenv()

app = Flask(__name__, 
    template_folder='../frontend/templates',
    static_folder='../frontend/static')
CORS(app)

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:112003@localhost/bookbuddy'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-secret-key')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255))
    is_admin = db.Column(db.Boolean, default=False)
    reviews = db.relationship('Review', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    category = db.Column(db.String(50))
    image_url = db.Column(db.String(200))
    reviews = db.relationship('Review', backref='book', lazy=True)
    published_date = db.Column(db.String(20))
    publisher = db.Column(db.String(100))
    page_count = db.Column(db.Integer)
    language = db.Column(db.String(10))
    isbn = db.Column(db.String(13))
    average_rating = db.Column(db.Float)
    ratings_count = db.Column(db.Integer)

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

# Routes
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 400
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already exists'}), 400
    
    user = User(username=data['username'], email=data['email'])
    user.set_password(data['password'])
    
    db.session.add(user)
    db.session.commit()
    
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    
    if user and user.check_password(data['password']):
        login_user(user)
        return jsonify({
            'message': 'Logged in successfully',
            'username': user.username,
            'is_admin': user.is_admin
        })
    
    return jsonify({'error': 'Invalid username or password'}), 401

@app.route('/api/auth/logout', methods=['GET', 'POST'])
def logout():
    if current_user.is_authenticated:
        logout_user()
    return jsonify({'message': 'Logged out successfully'})

@app.route('/api/books', methods=['GET'])
def get_books():
    try:
        # Get query parameters
        category = request.args.get('category')
        search = request.args.get('search')
        
        # Start with base query
        query = Book.query
        
        # Apply category filter if provided
        if category:
            query = query.filter(Book.category == category)
        
        # Apply search filter if provided
        if search:
            search_term = f'%{search}%'
            query = query.filter(
                or_(
                    Book.title.ilike(search_term),
                    Book.author.ilike(search_term),
                    Book.description.ilike(search_term)
                )
            )
        
        # Get all books
        books = query.all()
        
        # Convert to JSON
        books_json = [{
            'id': book.id,
            'title': book.title,
            'author': book.author,
            'description': book.description,
            'category': book.category,
            'image_url': book.image_url,
            'published_date': book.published_date,
            'publisher': book.publisher,
            'page_count': book.page_count,
            'language': book.language,
            'isbn': book.isbn,
            'average_rating': book.average_rating,
            'ratings_count': book.ratings_count
        } for book in books]
        
        return jsonify(books_json)
    except Exception as e:
        print(f"Error fetching books: {str(e)}")
        return jsonify({'error': 'Failed to fetch books'}), 500

@app.route('/api/books/<int:book_id>', methods=['GET'])
def get_book(book_id):
    try:
        book = Book.query.get_or_404(book_id)
        return jsonify({
            'id': book.id,
            'title': book.title,
            'author': book.author,
            'description': book.description,
            'category': book.category,
            'image_url': book.image_url,
            'published_date': book.published_date,
            'publisher': book.publisher,
            'page_count': book.page_count,
            'language': book.language,
            'isbn': book.isbn,
            'average_rating': book.average_rating,
            'ratings_count': book.ratings_count
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/books', methods=['POST'])
@login_required
def add_book():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    book = Book(
        title=data['title'],
        author=data['author'],
        description=data.get('description', ''),
        category=data.get('category', ''),
        image_url=data.get('image_url', ''),
        published_date=data.get('published_date', ''),
        publisher=data.get('publisher', ''),
        page_count=data.get('page_count', 0),
        language=data.get('language', 'en'),
        isbn=data.get('isbn', ''),
        average_rating=data.get('average_rating', 0),
        ratings_count=data.get('ratings_count', 0)
    )
    
    db.session.add(book)
    db.session.commit()
    
    return jsonify({'message': 'Book added successfully', 'id': book.id}), 201

@app.route('/api/init-data', methods=['POST'])
def init_data():
    try:
        # Popular book categories to search
        categories = [
            'fiction',
            'science fiction',
            'fantasy',
            'mystery',
            'romance',
            'biography',
            'history',
            'science',
            'technology',
            'philosophy'
        ]
        
        books_added = 0
        total_books_needed = 20
        
        # Fallback images for different categories
        fallback_images = {
            'fiction': 'https://images.unsplash.com/photo-1544947950-fa07a98d237f?w=500',
            'science fiction': 'https://images.unsplash.com/photo-1532012197267-da84d127e765?w=500',
            'fantasy': 'https://images.unsplash.com/photo-1543002588-bfa74002ed7e?w=500',
            'mystery': 'https://images.unsplash.com/photo-1512820790803-83ca734da794?w=500',
            'romance': 'https://images.unsplash.com/photo-1541963463532-d68292c34b19?w=500',
            'biography': 'https://images.unsplash.com/photo-1544716278-ca5e3f4abd8c?w=500',
            'history': 'https://images.unsplash.com/photo-1507842217343-583bb7270b66?w=500',
            'science': 'https://images.unsplash.com/photo-1532012197267-da84d127e765?w=500',
            'technology': 'https://images.unsplash.com/photo-1517694712202-14dd9538aa97?w=500',
            'philosophy': 'https://images.unsplash.com/photo-1507842217343-583bb7270b66?w=500'
        }
        
        for category in categories:
            if books_added >= total_books_needed:
                break
                
            # Search Google Books API
            api_url = f'https://www.googleapis.com/books/v1/volumes?q=subject:{category}&maxResults=40&langRestrict=en&orderBy=relevance'
            response = requests.get(api_url)
            data = response.json()
            
            if 'items' in data:
                for item in data['items']:
                    if books_added >= total_books_needed:
                        break
                        
                    volume_info = item['volumeInfo']
                    
                    # Skip books without essential information
                    if not volume_info.get('title') or not volume_info.get('authors'):
                        continue
                    
                    # Check if book already exists
                    existing_book = Book.query.filter_by(
                        title=volume_info.get('title', ''),
                        author=', '.join(volume_info.get('authors', ['Unknown']))
                    ).first()
                    
                    if not existing_book:
                        # Get image URL or use fallback
                        image_url = volume_info.get('imageLinks', {}).get('thumbnail', '')
                        if not image_url:
                            image_url = fallback_images.get(category.lower(), 'https://images.unsplash.com/photo-1544947950-fa07a98d237f?w=500')
                        
                        # Clean up image URL for better quality
                        if image_url:
                            image_url = image_url.replace('&edge=curl', '').replace('zoom=1', 'zoom=2')
                        
                        # Extract book information
                        book = Book(
                            title=volume_info.get('title', ''),
                            author=', '.join(volume_info.get('authors', ['Unknown'])),
                            description=volume_info.get('description', 'No description available'),
                            category=category.capitalize(),
                            image_url=image_url,
                            published_date=volume_info.get('publishedDate', ''),
                            publisher=volume_info.get('publisher', 'Unknown'),
                            page_count=volume_info.get('pageCount', 0),
                            language=volume_info.get('language', 'en'),
                            isbn=next((identifier['identifier'] for identifier in volume_info.get('industryIdentifiers', []) 
                                    if identifier['type'] == 'ISBN_13'), ''),
                            average_rating=volume_info.get('averageRating', 0),
                            ratings_count=volume_info.get('ratingsCount', 0)
                        )
                        
                        db.session.add(book)
                        books_added += 1
        
        db.session.commit()
        return jsonify({
            'message': f'Successfully added {books_added} new books',
            'books_added': books_added
        }), 201
        
    except Exception as e:
        db.session.rollback()
        print(f"Error initializing data: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/books/<int:book_id>')
def book_details(book_id):
    try:
        book = Book.query.get_or_404(book_id)
        return render_template('book_details.html', book=book)
    except Exception as e:
        print(f"Error loading book details: {str(e)}")
        return redirect(url_for('index'))

@app.route('/api/books/<int:book_id>/reviews', methods=['POST'])
@login_required
def add_review(book_id):
    data = request.get_json()
    
    review = Review(
        content=data['content'],
        rating=data['rating'],
        user_id=current_user.id,
        book_id=book_id
    )
    
    db.session.add(review)
    db.session.commit()
    
    return jsonify({
        'message': 'Review added successfully',
        'review': {
            'id': review.id,
            'content': review.content,
            'rating': review.rating,
            'user': current_user.username,
            'created_at': review.created_at.isoformat()
        }
    }), 201

@app.route('/api/books/<int:book_id>/reviews', methods=['GET'])
def get_book_reviews(book_id):
    try:
        reviews = Review.query.filter_by(book_id=book_id).order_by(Review.created_at.desc()).all()
        return jsonify([{
            'id': review.id,
            'user': review.user.username,
            'rating': review.rating,
            'content': review.content,
            'created_at': review.created_at.isoformat()
        } for review in reviews])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    return render_template('admin_dashboard.html')

@app.route('/api/auth/check-admin')
@login_required
def check_admin():
    return jsonify({
        'username': current_user.username,
        'is_admin': current_user.is_admin
    })

@app.route('/api/admin/users')
@login_required
def get_users():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    users = User.query.all()
    return jsonify([{
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'is_admin': user.is_admin,
        'reviews': len(user.reviews)
    } for user in users])

@app.route('/api/admin/users/<int:user_id>/toggle-admin', methods=['POST'])
@login_required
def toggle_admin_status(user_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    user = User.query.get_or_404(user_id)
    data = request.get_json()
    
    user.is_admin = data.get('make_admin', False)
    db.session.commit()
    
    return jsonify({'message': 'User status updated successfully'})

@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    user = User.query.get_or_404(user_id)
    
    # Don't allow deleting the last admin
    if user.is_admin and User.query.filter_by(is_admin=True).count() <= 1:
        return jsonify({'error': 'Cannot delete the last admin user'}), 400
    
    db.session.delete(user)
    db.session.commit()
    
    return jsonify({'message': 'User deleted successfully'})

@app.route('/api/admin/reviews')
@login_required
def get_all_reviews():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    reviews = Review.query.all()
    return jsonify([{
        'id': review.id,
        'content': review.content,
        'rating': review.rating,
        'created_at': review.created_at.isoformat(),
        'user': {
            'username': review.user.username
        },
        'book': {
            'title': review.book.title
        }
    } for review in reviews])

@app.route('/api/admin/reviews/<int:review_id>', methods=['DELETE'])
@login_required
def delete_review(review_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    review = Review.query.get_or_404(review_id)
    db.session.delete(review)
    db.session.commit()
    
    return jsonify({'message': 'Review deleted successfully'})

@app.route('/api/books/<int:book_id>', methods=['PUT'])
@login_required
def update_book(book_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    book = Book.query.get_or_404(book_id)
    data = request.get_json()
    
    book.title = data.get('title', book.title)
    book.author = data.get('author', book.author)
    book.description = data.get('description', book.description)
    book.category = data.get('category', book.category)
    book.image_url = data.get('image_url', book.image_url)
    book.published_date = data.get('published_date', book.published_date)
    book.publisher = data.get('publisher', book.publisher)
    book.page_count = data.get('page_count', book.page_count)
    book.language = data.get('language', book.language)
    book.isbn = data.get('isbn', book.isbn)
    book.average_rating = data.get('average_rating', book.average_rating)
    book.ratings_count = data.get('ratings_count', book.ratings_count)
    
    db.session.commit()
    
    return jsonify({'message': 'Book updated successfully'})

@app.route('/api/books/<int:book_id>', methods=['DELETE'])
@login_required
def delete_book(book_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    book = Book.query.get_or_404(book_id)
    db.session.delete(book)
    db.session.commit()
    
    return jsonify({'message': 'Book deleted successfully'})

@app.route('/api/books/search')
def search_books():
    query = request.args.get('q', '').strip()
    if not query:
        return jsonify([])
    
    try:
        # Search in local database first
        local_books = Book.query.filter(
            or_(
                Book.title.ilike(f'%{query}%'),
                Book.author.ilike(f'%{query}%'),
                Book.description.ilike(f'%{query}%')
            )
        ).all()
        
        # If we have enough local results, return them
        if len(local_books) >= 5:
            return jsonify([{
                'id': book.id,
                'title': book.title,
                'author': book.author,
                'description': book.description,
                'category': book.category,
                'image_url': book.image_url,
                'published_date': book.published_date,
                'publisher': book.publisher,
                'page_count': book.page_count,
                'language': book.language,
                'isbn': book.isbn,
                'average_rating': book.average_rating,
                'ratings_count': book.ratings_count
            } for book in local_books])
        
        # Search in Google Books API
        api_url = f'https://www.googleapis.com/books/v1/volumes?q={query}&maxResults=20'
        response = requests.get(api_url)
        data = response.json()
        
        books = []
        if 'items' in data:
            for item in data['items']:
                volume_info = item['volumeInfo']
                
                # Extract book information
                book = {
                    'title': volume_info.get('title', ''),
                    'author': ', '.join(volume_info.get('authors', ['Unknown'])),
                    'description': volume_info.get('description', 'No description available'),
                    'category': volume_info.get('categories', ['Uncategorized'])[0] if volume_info.get('categories') else 'Uncategorized',
                    'image_url': volume_info.get('imageLinks', {}).get('thumbnail', ''),
                    'published_date': volume_info.get('publishedDate', ''),
                    'publisher': volume_info.get('publisher', 'Unknown'),
                    'page_count': volume_info.get('pageCount', 0),
                    'language': volume_info.get('language', 'en'),
                    'isbn': next((identifier['identifier'] for identifier in volume_info.get('industryIdentifiers', []) 
                                if identifier['type'] == 'ISBN_13'), ''),
                    'average_rating': volume_info.get('averageRating', 0),
                    'ratings_count': volume_info.get('ratingsCount', 0)
                }
                
                # Clean up image URL for better quality
                if book['image_url']:
                    book['image_url'] = book['image_url'].replace('&edge=curl', '').replace('zoom=1', 'zoom=2')
                
                books.append(book)
        
        return jsonify(books)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/check')
def check_auth():
    try:
        if current_user.is_authenticated:
            return jsonify({
                'authenticated': True,
                'username': current_user.username,
                'is_admin': current_user.is_admin
            })
        return jsonify({
            'authenticated': False,
            'username': None,
            'is_admin': False
        })
    except Exception as e:
        print(f"Error in check_auth: {str(e)}")
        return jsonify({
            'authenticated': False,
            'username': None,
            'is_admin': False
        })

@app.route('/api/books/fetch-by-isbn/<isbn>', methods=['GET'])
@login_required
def fetch_book_by_isbn(isbn):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        # Fetch book details from Google Books API
        response = requests.get(f'https://www.googleapis.com/books/v1/volumes?q=isbn:{isbn}')
        data = response.json()
        
        if 'items' not in data or not data['items']:
            return jsonify({'error': 'Book not found'}), 404
        
        book_info = data['items'][0]['volumeInfo']
        
        # Extract relevant information
        book_data = {
            'title': book_info.get('title', ''),
            'author': ', '.join(book_info.get('authors', ['Unknown'])),
            'description': book_info.get('description', ''),
            'image_url': book_info.get('imageLinks', {}).get('thumbnail', ''),
            'category': book_info.get('categories', [''])[0] if book_info.get('categories') else '',
            'published_date': book_info.get('publishedDate', ''),
            'publisher': book_info.get('publisher', ''),
            'page_count': book_info.get('pageCount', 0),
            'language': book_info.get('language', 'en'),
            'isbn': isbn
        }
        
        return jsonify(book_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True) 