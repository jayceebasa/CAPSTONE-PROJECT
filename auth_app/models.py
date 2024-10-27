from django.db import models

from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    is_subscribed = models.BooleanField(default=False)
    first_name = models.CharField(max_length=255)  # Pangalan ng user
    last_name = models.CharField(max_length=255)   # Apelyido ng user
    email = models.CharField(max_length=255, unique=True)  # Email ng user, dapat unique
    username = models.CharField(max_length=150, unique=True)
    password = models.CharField(max_length=255)   # Password ng user
    address = models.TextField(null=True)  # Address ng user
    PhoneNumber = models.CharField(max_length=255, null=True)  # Phone
    picture = models.ImageField(upload_to='profile_pictures/', blank=True, null=True, default='profile_pictures/default_profpic.png')
    qrcode = models.ImageField(upload_to='qrcodes/', null=True, blank=True)
    role = models.CharField(max_length=50, choices=[('admin', 'Admin'), ('user', 'User'), ('Seller', 'seller')], default='User')
    email_verification_token = models.CharField(max_length=32, blank=True, null=True)  # Add this line

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = []
    
class Product(models.Model):
    seller = models.ForeignKey(User, on_delete=models.CASCADE, default=None)
    name = models.CharField(max_length=255)
    image = models.ImageField(upload_to='product_images/')
    price = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    description = models.TextField(null=True, blank=True)
    stock = models.IntegerField(default=0)
    type = models.CharField(max_length=50, default='product')  # e.g., 'art', 'mugs'
    category = models.CharField(max_length=50, default='product')  # e.g., 'paintings', 'handicrafts'

class Transaction(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=0)
    status = models.CharField(max_length=50)  # e.g., 'completed', 'pending'
    date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.product.name} - {self.amount}"

class Cart(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

class CartItem(models.Model):
    cart = models.ForeignKey(Cart, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField(default=1)
    
class UserAddress(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    address = models.TextField()
    is_default = models.BooleanField(default=False)
    
class LoginEvent(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)