from django.urls import path
from .views import CustomAuthToken, register, ListUsers
from . import views

app_name = 'core' 

urlpatterns = [
    path('', views.index, name='index'),
    path('shop/', views.shop_view, name = 'shop'),
    path('users/', views.user_profile,  name = 'users'),
    path('seller/', views.seller_profile, name = 'sellers'),
    path('login/', views.login_view, name = 'login'),
    path('register/', views.register_user, name='reg_user'),
    path('register_seller/', views.register_seller, name='reg_seller'),
    path('home/', views.index, name='home'),
    path('logout/', views.logout_view, name='logout'),
    path('transaction_history/', views.transaction_history, name='transaction_history'),
    path('change-status-delivered/', views.change_status_delivered, name='change_status_delivered'),
    path('change-status/', views.change_status, name='change_status'),
    path('product/<int:id>/', views.single_product, name='single_product'),
    path('adminview/', views.admin_view, name='admin'),
    
    #API URLS
    path('api/users/', ListUsers.as_view(), name='List-users'),
    path('api/token/auth/', CustomAuthToken.as_view(), name='api_token_auth'),
    path('api/register/', register.as_view(), name='Register'),
    path('api/upload_profile_picture/', views.user_profile, name='upload_profile_picture'),
    path('api/add_transaction/', views.add_transaction, name='add_transaction'),
    path('api/add_product/', views.add_product, name='add_product'),
    path('api/seller/<int:seller_id>/products/', views.SellerProductsView.as_view(), name='seller_products'),
    path('update_profile/', views.update_profile, name='update_profile'),
    path('change_password/', views.change_password, name='change_password'),
    path('add-to-cart/<int:product_id>/', views.add_to_cart, name='add_to_cart'),
    path('cart/', views.cart_detail, name='cart_detail'),
    path('remove-from-cart/<int:item_id>/', views.remove_from_cart, name='remove_from_cart'),
    path('update-cart-item/<int:item_id>/', views.update_cart_item, name='update_cart_item'),
    path('update_product/<int:product_id>/', views.update_product, name='update_product'),
    path('delete_product/<int:product_id>/', views.delete_product, name='delete_product'),
    path('verify-email/<str:token>/', views.VerifyEmail.as_view(), name='verify-email'),
    path('save-selected-address/', views.save_selected_address, name='save_selected_address'),
    path('save-address/', views.save_address, name='save_address'),
    path('get-addresses/', views.get_addresses, name='get_addresses'),
    path('api/login-data/', views.login_data, name='login-data'),
    path('api/sales-today/', views.sales_today, name='sales-today'),
    path('api/total-sales/', views.total_sales, name='total-sales'),
    path('api/pending-orders/', views.pending_orders, name='pending-orders'),
    path('api/user-creation-data/', views.user_creation_data, name='user-creation-data'),
    path('api/toggle-user-status/<int:user_id>/', views.toggle_user_status, name='toggle_user_status'),
    path('change-admin-passowrd', views.change_admin_password, name='change_admin_password'),
    path('delete-address/', views.delete_address, name='delete_address'),
    path('shop/pagination/', views.shop_pagination, name='shop_pagination'),
]