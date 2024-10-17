from .models import Cart, CartItem

def cart_item_count(request):
    if request.user.is_authenticated:
        cart, created = Cart.objects.get_or_create(user=request.user)
        total_items = CartItem.objects.filter(cart=cart).count()
    else:
        total_items = 0
    return {'cart_item_count': total_items}