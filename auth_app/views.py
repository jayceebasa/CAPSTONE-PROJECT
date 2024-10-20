# views.py
from rest_framework.views import APIView
from .serializers import UserSerializer, TransactionSerializer
from rest_framework.response import Response 
from .models import User, Transaction, Product, Cart, CartItem, UserAddress
from django.conf import settings
from django.db.models import Q
from django.contrib.auth.hashers import make_password
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.response import Response
from rest_framework import status
import jwt
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from django.contrib.auth import login as auth_login, logout as auth_logout, authenticate
from django.shortcuts import redirect
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.models import User
from rest_framework import status
from rest_framework import authentication, permissions
from rest_framework.views import APIView
from django.http import JsonResponse
from .forms import ProfileImageForm
from rest_framework.decorators import api_view
from .serializers import ProductSerializer
from rest_framework.decorators import permission_classes
from rest_framework import generics
from .models import Product
from django.views.decorators.csrf import csrf_exempt
from django.core.paginator import Paginator
from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth import get_user_model
import time
import json
import logging
from django.shortcuts import render, get_object_or_404
import random
from django.core.mail import send_mail
from django.utils.crypto import get_random_string
from django.template.loader import render_to_string
logger = logging.getLogger(__name__)

User = get_user_model()

class Register(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        username = request.data.get('username')
        email = request.data.get('email')

        if User.objects.filter(username=username).exists():
            return Response({'error': 'Username already exists'}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(email=email).exists():
            return Response({'error': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response({
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@login_required
@login_required
def index(request):
    user = request.user
    if user.is_authenticated and user.role == 'Admin':
        return render(request, 'core/admin.html')
    
    all_products = list(Product.objects.all())
    related_products = random.sample(all_products, min(len(all_products), 3))
    return render(request, 'core/index.html', {'all_products': all_products, 'related_products': related_products})

@login_required
def shop_view(request):
    products = Product.objects.all()
    product_types = Product.objects.values_list('type', flat=True).distinct()
    return render(request, 'core/shop.html', {'products': products, 'product_types': product_types})
  
@login_required
def user_profile(request):
    if request.method == 'POST':
        form = ProfileImageForm(request.POST, request.FILES, instance=request.user)
        if form.is_valid():
            form.save()
            return JsonResponse({'success': True})
        else:
            return JsonResponse({'success': False, 'error': form.errors})
    else:
        form = ProfileImageForm(instance=request.user)

    # Fetch transactions and apply pagination
    transactions = Transaction.objects.filter(user=request.user).order_by('-date')
    paginator = Paginator(transactions, 4)  # Show 4 transactions per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    return render(request, 'core/prof_user.html', {
        'form': form,
        'user': request.user,
        'transactions': page_obj
    })

# views.py

@login_required
def seller_profile(request):
    if request.method == 'POST':
        form = ProfileImageForm(request.POST, request.FILES, instance=request.user)
        if form.is_valid():
            form.save()
            return JsonResponse({'success': True})
        else:
            return JsonResponse({'success': False, 'error': form.errors})
    else:
        form = ProfileImageForm(instance=request.user)

    user_products = Product.objects.filter(seller=request.user)
    transactions = Transaction.objects.filter(product__seller=request.user).order_by('-date')

    # Pagination
    paginator = Paginator(user_products, 4)  # Show 4 products per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    # Pagination for transactions
    transaction_paginator = Paginator(transactions, 4)  # Show 4 transactions per page
    transaction_page_number = request.GET.get('transaction_page')
    transaction_page_obj = transaction_paginator.get_page(transaction_page_number)

    return render(request, 'core/prof_seller.html', {
        'form': form,
        'user': request.user,
        'products': page_obj,
        'transactions': transaction_page_obj
    })

def admin_view(request):
    return render(request, 'core/admin.html')

@login_required
def transaction_history(request):
    transactions = Transaction.objects.filter(user=request.user).order_by('-date')
    return render(request, 'core/prof_user.html', {'transactions': transactions})

def logout_view(request):
    auth_logout(request)  # Log out the user
    return redirect('/login/')  # Redirect to the login page after logout

def register_user(request):
    return render(request, 'core/reg_user.html')
  
def register_seller(request):
  return render(request, 'core/reg_seller.html')

def login_view(request):
    # Clear all previous messages
    storage = messages.get_messages(request)
    for _ in storage:
        pass

    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)
        if user is not None:
            if not user.is_active:
                messages.error(request, 'You need to verify your email first.')
                return render(request, 'core/login.html')
            
            auth_login(request, user)  # Log in the user using Django's session framework

            # Check the user's role and redirect accordingly
            if user.role == 'Admin':
                return redirect('core:admin')
            elif user.role == 'Seller':
                return redirect('core:sellers')
            else:
                return redirect('core:index')
        else:
            # Check if the user exists but is not active
            try:
                user = User.objects.get(username=username)
                if not user.is_active:
                    messages.error(request, 'You need to verify your email first.')
                else:
                    messages.error(request, 'Invalid username or password.')
            except User.DoesNotExist:
                messages.error(request, 'Invalid username or password.')
            return render(request, 'core/login.html')
    return render(request, 'core/login.html')

class CustomAuthToken(ObtainAuthToken):

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        return Response({
            'message': 'You have successfully logged in.',
            'token': token.key
        })

class ListUsers(APIView):
    authentication_classes = [authentication.TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, format=None):
        token = request.auth
        user_data = [
            {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name
            }
            for user in User.objects.filter(auth_token=token)
        ]
        return Response(user_data)

    def post(self, request, *args, **kwargs):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response({
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class RegisterView(APIView):    
    def post(self, request):
        serializer = UserSerializer(data=request.data)  # Gamitin ang UserSerializer para sa validation ng data
        serializer.is_valid(raise_exception=True)  # I-validate ang data, kung may error, itaas ang exception
        serializer.save()  # I-save ang validated na data sa database
        return Response(serializer.data)  # I-return ang serialized na data bilang response

class register(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        try:
            username = request.data.get('username')
            email = request.data.get('email')
            role = request.data.get('role')  # Add role to distinguish between user and seller

            if User.objects.filter(username=username).exists():
                return Response({'error': 'Username already exists.'}, status=status.HTTP_400_BAD_REQUEST)

            if User.objects.filter(email=email).exists():
                return Response({'error': 'Email already exists.'}, status=status.HTTP_400_BAD_REQUEST)

            email_verification_token = get_random_string(32)
            request.data['email_verification_token'] = email_verification_token

            serializer = UserSerializer(data=request.data)
            if serializer.is_valid():
                user = serializer.save()
                user.is_active = False  # Deactivate account until it is verified
                user.email_verification_token = email_verification_token  # Set the token
                user.role = role  # Set the role
                user.save()

                verification_link = request.build_absolute_uri(f'/verify-email/{email_verification_token}/')
                email_body = render_to_string('core/email_verification.txt', {
                    'user': user,
                    'verification_link': verification_link
                })

                send_mail(
                    'Verify your email',
                    email_body,
                    'from@example.com',
                    [email],
                    fail_silently=False,
                )

                return Response({'message': 'User registered successfully. Please check your email to verify your account.'}, status=status.HTTP_201_CREATED)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': f'An error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class VerifyEmail(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request, token):
        try:
            user = User.objects.get(email_verification_token=token)
            user.is_active = True
            user.email_verification_token = ''
            user.save()
            messages.success(request, 'Email verified successfully. You can now log in.')
            return redirect('core:login')  # Redirect to the login page
        except User.DoesNotExist:
            messages.error(request, 'Invalid token.')
            return redirect('core:login')  # Redirect to the login page

class adminUpdateUsersView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

    def put(self, request):
        username = request.data.get('username')
        email = request.data.get('email')
        password = request.data.get('password')  # Get the password from the request
        
        if username is None or email is None:
            return Response({'error': 'Username and email are required'}, status=400)
        
        try:
            user = User.objects.get(username=username)
            if password:
                request.data['password'] = make_password(password)
            
            serializer = UserSerializer(instance=user, data=request.data, partial=True)  
            serializer.is_valid(raise_exception=True)
            
            serializer.save()
            return Response(serializer.data)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=404)
            

    def delete(self, request):
        try:
            username = request.data.get('username')
            email = request.data.get('email')
            if username is None and email is None:
                return Response({'error': 'Username or email is required'}, status=400)

            
            user = User.objects.get(Q(username=username) | Q(email=email))
            user.delete()

            return Response('User deleted')
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=404)
        
@api_view(['POST'])
def add_transaction(request):
    if request.method == 'POST':
        serializer = TransactionSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
      
@api_view(['POST'])
def add_product(request):
    if request.method == 'POST':
        serializer = ProductSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
      
class SellerProductsView(generics.ListAPIView):
    serializer_class = ProductSerializer

    def get_queryset(self):
        seller_id = self.kwargs['seller_id']
        return Product.objects.filter(seller_id=seller_id)

@login_required
@csrf_exempt
def change_status_delivered(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body.decode('utf-8'))
            transaction_id = data.get('transaction_id')
            new_status = data.get('status')
            logger.debug(f"Received data: {data}")  # Debugging log
            try:
                transaction = Transaction.objects.get(id=transaction_id, user=request.user)
                transaction.status = new_status
                transaction.save()
                logger.debug(f"Transaction {transaction_id} status changed to {new_status}")  # Debugging log
                return JsonResponse({'success': True})
            except Transaction.DoesNotExist:
                logger.error(f"Transaction {transaction_id} not found")  # Debugging log
                return JsonResponse({'success': False, 'error': 'Transaction not found'})
        except json.JSONDecodeError:
            logger.error("Invalid JSON received")  # Debugging log
            return JsonResponse({'success': False, 'error': 'Invalid JSON'})
    logger.error("Invalid request method")  # Debugging log
    return JsonResponse({'success': False, 'error': 'Invalid request method'})

@login_required
@csrf_exempt  
def change_status(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            transaction_id = data.get('transaction_id')
            new_status = data.get('status')
            logger.debug(f"Received data: {data}")  # Debugging log
            try:
                transaction = Transaction.objects.get(id=transaction_id, product__seller=request.user)
                transaction.status = new_status
                transaction.save()
                logger.debug(f"Transaction {transaction_id} status changed to {new_status}")  # Debugging log
                return JsonResponse({'success': True})
            except Transaction.DoesNotExist:
                logger.error(f"Transaction {transaction_id} not found")  # Debugging log
                return JsonResponse({'success': False, 'error': 'Transaction not found'})
        except json.JSONDecodeError:
            logger.error("Invalid JSON received")  # Debugging log
            return JsonResponse({'success': False, 'error': 'Invalid JSON'})
    logger.error("Invalid request method")  # Debugging log
    return JsonResponse({'success': False, 'error': 'Invalid request method'})
  
@login_required
def update_profile(request):
    if request.method == 'POST':
        user = request.user
        user.first_name = request.POST.get('first_name')
        user.last_name = request.POST.get('last_name')
        user.PhoneNumber = request.POST.get('PhoneNumber')
        user.email = request.POST.get('email')
        user.address = request.POST.get('address')
        user.save()
        messages.success(request, 'Profile updated successfully')
        user_role = request.POST.get('user_role')
        
        if user_role == 'Seller':
            return redirect('/seller/')
        else:     
          return redirect('/users/')  # Redirect to the profile page after saving
    else:
        return render(request, 'core/prof_user.html', {'user': request.user})
  

@login_required
def change_password(request):
    if request.method == 'POST':
        current_password = request.POST.get('current_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')
        user_role = request.POST.get('user_role')  # Get the user role from the form data

        # Fetch products and transactions to include in the context
        products = Product.objects.filter(seller=request.user)
        transactions = Transaction.objects.filter(user=request.user)  # Adjust this based on your model

        if user_role == 'Seller':
            if not request.user.check_password(current_password):
                return render(request, 'core/prof_seller.html', {
                    'alert': 'Current password is incorrect',
                    'products': products,
                    'transactions': transactions,
                    'user_role': user_role
                })

            if new_password != confirm_password:
                return render(request, 'core/prof_seller.html', {
                    'alert': 'Passwords do not match',
                    'products': products,
                    'transactions': transactions,
                    'user_role': user_role
                })
            else:
                request.user.set_password(new_password)
                request.user.save()
                update_session_auth_hash(request, request.user)  # Important to keep the user logged in
                return render(request, 'core/prof_seller.html', {
                    'success': 'Password changed successfully',
                    'products': products,
                    'transactions': transactions,
                    'user_role': user_role
                })
        else:
            if not request.user.check_password(current_password):
                return render(request, 'core/prof_user.html', {
                    'alert': 'Current password is incorrect',
                    'products': products,
                    'transactions': transactions,
                    'user_role': user_role
                })

            if new_password != confirm_password:
                return render(request, 'core/prof_user.html', {
                    'alert': 'Passwords do not match',
                    'products': products,
                    'transactions': transactions,
                    'user_role': user_role
                })
            else:
                request.user.set_password(new_password)
                request.user.save()
                update_session_auth_hash(request, request.user)  # Important to keep the user logged in
                return render(request, 'core/prof_user.html', {
                    'success': 'Password changed successfully',
                    'products': products,
                    'transactions': transactions,
                    'user_role': user_role
                })

    # Fetch products and transactions to include in the context for the initial GET request
    products = Product.objects.filter(seller=request.user)
    transactions = Transaction.objects.filter(user=request.user)  # Adjust this based on your model
    user_role = 'Seller' if request.user.is_seller else 'User'  # Adjust this based on your user model
    return render(request, 'core/prof_seller.html', {
        'products': products,
        'transactions': transactions,
        'user_role': user_role
    }) 

def single_product(request, id):
    product = get_object_or_404(Product, id=id)
    all_products = list(Product.objects.exclude(id=product.id))
    related_products = random.sample(all_products, min(len(all_products), 3))
    return render(request, 'core/single-product.html', {'product': product, 'related_products': related_products})
  
@login_required
def add_to_cart(request, product_id):
    if request.method == 'POST':
        product = get_object_or_404(Product, id=product_id)
        quantity = int(request.POST.get('quantity', 1))
        cart, created = Cart.objects.get_or_create(user=request.user)
        cart_item, created = CartItem.objects.get_or_create(cart=cart, product=product)
        
        # If the cart item already exists, update the quantity
        if not created:
            cart_item.quantity += quantity
        else:
            cart_item.quantity = quantity
        
        cart_item.save()
        
        total_items = CartItem.objects.filter(cart=cart).count()
        return JsonResponse({'total_items': total_items})
    
    return JsonResponse({'error': 'Invalid request'}, status=400)
  
@login_required
def cart_detail(request):
    cart = get_object_or_404(Cart, user=request.user)
    cart_items = CartItem.objects.filter(cart=cart)
    total_price = 0
    for item in cart_items:
        item.total_price = item.product.price * item.quantity
        total_price += item.total_price
    return render(request, 'core/cart.html', {'cart_items': cart_items, 'total_price': total_price})
  
@login_required
def remove_from_cart(request, item_id):
    cart_item = get_object_or_404(CartItem, id=item_id, cart__user=request.user)
    cart_item.delete()
    
    # Calculate the new total price for the cart
    cart_items = CartItem.objects.filter(cart=cart_item.cart)
    total_price = sum(item.product.price * item.quantity for item in cart_items)
    
    return JsonResponse({
        'total_price': total_price
    })

@login_required
def update_cart_item(request, item_id):
    cart_item = get_object_or_404(CartItem, id=item_id, cart__user=request.user)
    if request.method == 'POST':
        quantity = int(request.POST.get('quantity', 1))
        if quantity > cart_item.product.stock:
            quantity = cart_item.product.stock
        cart_item.quantity = quantity
        cart_item.save()
        
        # Calculate the new total price for the cart
        cart_items = CartItem.objects.filter(cart=cart_item.cart)
        total_price = sum(item.product.price * item.quantity for item in cart_items)
        
        return JsonResponse({
            'item_total_price': cart_item.product.price * cart_item.quantity,
            'total_price': total_price
        })
    return JsonResponse({'error': 'Invalid request'}, status=400)


def update_product(request, product_id):
    product = get_object_or_404(Product, id=product_id)
    product.name = request.POST.get('name')
    product.price = request.POST.get('price')
    product.stock = request.POST.get('stock')
    product.category = request.POST.get('editCategory')
    product.type = request.POST.get('type')
    product.description = request.POST.get('description')
    if 'image' in request.FILES:
        product.image = request.FILES['image']
    product.save()
    return JsonResponse({'success': True})


def delete_product(request, product_id):
    product = get_object_or_404(Product, id=product_id)
    product.delete()
    return JsonResponse({'success': True})


def save_selected_address(request):
    address = request.POST.get('address')
    if address:
        user = request.user
        user.address = address  # Assuming the address field is named 'address'
        user.save()
        return JsonResponse({'success': True})
    return JsonResponse({'success': False, 'error': 'No address provided'})
  
@csrf_exempt
@login_required
def save_address(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        full_address = data.get('address')
        if full_address:
            UserAddress.objects.create(user=request.user, address=full_address)
            return JsonResponse({'success': True})
        return JsonResponse({'success': False, 'error': 'Invalid address'})
    return JsonResponse({'success': False, 'error': 'Invalid request method'})

@login_required
def get_addresses(request):
    addresses = UserAddress.objects.filter(user=request.user).values_list('address', flat=True)
    selected_address = request.user.address if hasattr(request.user, 'address') else ""
    return JsonResponse({'success': True, 'addresses': list(addresses), 'selectedAddress': selected_address})