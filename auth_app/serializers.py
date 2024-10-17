from rest_framework import serializers
from .models import User
from django.contrib.auth.hashers import make_password
from .models import Transaction, Product
from django.utils import timezone
import pytz


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id','first_name','last_name','email','username','role','password']  # Mga field ng User model

        extra_kwargs = {
            'password': {'write_only': True}  # Ang password field ay para lang sa write, hindi ipapakita sa mga response
        }

    # Function para sa pag-create ng user base sa validated_data
    def create(self, validated_data):
        password = validated_data.pop('password', None)  # Alisin ang password mula sa validated_data

        instance = self.Meta.model(**validated_data)  # Gumawa ng instance ng User model gamit ang validated_data
        if password is not None:
            instance.set_password(password)  # I-set ang password gamit ang set_password method ng User model
        instance.save()  # I-save ang instance ng User model
        return instance

    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        if password:
            instance.set_password(password)  # Hash the password before saving
        instance.save()
        return instance
      
class TransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Transaction
        fields = ['user', 'product', 'amount', 'status', 'date']
        read_only_fields = ['date']
    
    def get_seller_id(self, obj):
        return obj.product.seller.id
     
    def create(self, validated_data):
        philippines_tz = pytz.timezone('Asia/Manila')
        validated_data['date'] = timezone.now().astimezone(philippines_tz) # Set the date to the current date and time
        return super().create(validated_data)

class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = ['name', 'image', 'price', 'description', 'stock', 'seller', 'type', 'category']