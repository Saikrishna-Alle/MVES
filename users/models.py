from datetime import timedelta
from django.utils import timezone
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
import uuid
import random
import string
from users.managers import CustomUserManager


class User(AbstractBaseUser, PermissionsMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    first_name = models.CharField(max_length=40)
    last_name = models.CharField(max_length=40)
    email = models.EmailField(unique=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    updated_on = models.DateTimeField(auto_now=True, null=True)
    is_active = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    last_login = models.DateTimeField(blank=True, null=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    EMAIL_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    class Meta:
        ordering = ['-created_on']
        verbose_name = 'user'
        verbose_name_plural = 'users'

    def __str__(self):
        return f"{self.first_name} {self.last_name}"


class UserRoles(models.Model):
    ROLES = [
        ('customer', 'Customer'),
        ('vendor', 'Vendor'),
        ('admin', 'Admin'),
        ('owner', 'Owner')
    ]
    user = models.OneToOneField(
        User, on_delete=models.CASCADE, primary_key=True)
    user_type = models.CharField(
        max_length=25, choices=ROLES, default='customer')

    def __str__(self):
        return f"{self.user.first_name} {self.user.last_name}"


class ActivationToken(models.Model):
    TOKEN_TYPES = (
        ('activation', 'Activation'),
        ('password_reset', 'Password Reset'),
    )

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    token_type = models.CharField(
        max_length=20, choices=TOKEN_TYPES)

    def save(self, *args, **kwargs):
        if not self.pk:
            if self.token_type == 'activation':
                self.expires_at = timezone.now() + timedelta(hours=1)
            elif self.token_type == 'password_reset':
                self.expires_at = timezone.now() + timedelta(hours=1)
        super().save(*args, **kwargs)

    def is_expired(self):
        return timezone.now() > self.expires_at


class Profiles(models.Model):
    user = models.OneToOneField(
        User, on_delete=models.CASCADE, unique=True, primary_key=True)
    phone_number = models.CharField(
        max_length=40, blank=True, null=True, unique=True)
    address = models.TextField(blank=True, null=True)
    gender = models.CharField(max_length=10, blank=True, null=True)
    profile_picture = models.ImageField(
        upload_to='profile_pictures/', blank=True, null=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    updated_on = models.DateTimeField(auto_now=True, null=True)


class Staff(models.Model):
    emp_id = models.CharField(max_length=7, unique=True, primary_key=True)
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    designation = models.CharField(max_length=100)
    exp_level = models.IntegerField(default=0)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    updated_on = models.DateTimeField(auto_now=True, null=True)

    def save(self, *args, **kwargs):
        if not self.emp_id:
            last_staff = Staff.objects.order_by('-emp_id').first()
            if last_staff:
                last_id = int(last_staff.emp_id[4:])
                new_id = f'MVES{str(last_id + 1).zfill(3)}'
            else:
                new_id = 'MVES001'
            self.emp_id = new_id

        super().save(*args, **kwargs)


class Vendor(models.Model):
    id = models.CharField(max_length=9, unique=True,
                          blank=True, primary_key=True)
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='vendors')
    name = models.CharField(max_length=255)
    phone = models.CharField(max_length=40)
    email = models.EmailField(blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    shop_type = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True)
    gstin_number = models.CharField(max_length=50, blank=True, null=True)
    business_license = models.CharField(max_length=255, blank=True, null=True)
    website_url = models.URLField(blank=True, null=True)
    ratings = models.DecimalField(max_digits=3, decimal_places=2, default=0.0)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    updated_on = models.DateTimeField(auto_now=True, null=True)

    def save(self, *args, **kwargs):
        if not self.id:
            self.id = self.generate_vendor_id()
        super().save(*args, **kwargs)

    def generate_vendor_id(self):
        base_id = ''.join(e for e in self.name if e.isalnum()).upper()
        if len(base_id) < 3:
            base_id = base_id.ljust(3, 'X')
        else:
            base_id = base_id[:3]

        random_part = ''.join(random.choices(base_id + string.digits, k=6))
        unique_id = base_id + random_part

        while Vendor.objects.filter(id=unique_id).exists():
            random_part = ''.join(random.choices(base_id + string.digits, k=6))
            unique_id = base_id + random_part

        return unique_id


class Category(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True, null=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    updated_on = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.name


class SubCategory(models.Model):
    id = models.AutoField(primary_key=True)
    category = models.ForeignKey(
        Category, on_delete=models.CASCADE, related_name='subcategories')
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    updated_on = models.DateTimeField(auto_now=True, null=True)

    class Meta:
        unique_together = ('category', 'name')

    def __str__(self):
        return f"{self.name} ({self.category.name})"


class Size(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=50, unique=True)
    description = models.TextField(blank=True, null=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    updated_on = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.name


class Product(models.Model):
    id = models.AutoField(primary_key=True)
    vendor = models.ForeignKey(
        Vendor, on_delete=models.CASCADE, related_name='products')
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    stock = models.PositiveIntegerField()
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    updated_on = models.DateTimeField(auto_now=True, null=True)
    sizes = models.ManyToManyField(Size, through='ProductSize', blank=True)

    def __str__(self):
        return self.name


class ProductCategory(models.Model):
    product = models.ForeignKey(
        Product, on_delete=models.CASCADE, related_name='product_categories')
    category = models.ForeignKey(
        Category, on_delete=models.CASCADE, related_name='product_categories')
    subcategory = models.ForeignKey(
        SubCategory, on_delete=models.CASCADE, related_name='product_categories', null=True, blank=True)
    added_on = models.DateTimeField(auto_now_add=True, null=True)

    class Meta:
        unique_together = ('product', 'category', 'subcategory')


class ProductSize(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    size = models.ForeignKey(Size, on_delete=models.CASCADE)
    stock = models.PositiveIntegerField()
    price_adjustment = models.DecimalField(
        max_digits=10, decimal_places=2, default=0.0)

    class Meta:
        unique_together = ('product', 'size')

    def __str__(self):
        return f"{self.product.name} - {self.size.name}"


class Order(models.Model):
    id = models.AutoField(primary_key=True)
    customer = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='orders')
    vendor = models.ForeignKey(
        Vendor, on_delete=models.CASCADE, related_name='orders')
    product = models.ForeignKey(
        Product, on_delete=models.CASCADE, related_name='orders')
    size = models.ForeignKey(
        Size, on_delete=models.CASCADE, null=True, blank=True)
    quantity = models.PositiveIntegerField()
    total_price = models.DecimalField(max_digits=10, decimal_places=2)
    order_date = models.DateTimeField(auto_now_add=True, null=True)
    status = models.CharField(max_length=20, choices=[('pending', 'Pending'), (
        'completed', 'Completed'), ('shipped', 'Shipped'), ('delivered', 'Delivered')])
    delivery_address = models.ForeignKey(
        'ShippingAddress', on_delete=models.SET_NULL, null=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    updated_on = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return f"Order {self.id} - {self.customer.email}"


class Cart(models.Model):
    customer = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='cart')
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    updated_on = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return f"Cart {self.id} - {self.customer.email}"


class CartItem(models.Model):
    cart = models.ForeignKey(
        Cart, on_delete=models.CASCADE, related_name='items')
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    size = models.ForeignKey(
        Size, on_delete=models.CASCADE, null=True, blank=True)
    quantity = models.PositiveIntegerField()
    added_on = models.DateTimeField(auto_now_add=True, null=True)

    def __str__(self):
        return f"{self.product.name} - {self.size.name if self.size else 'No size'} x {self.quantity}"


class Wishlist(models.Model):
    customer = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='wishlist')
    created_on = models.DateTimeField(auto_now_add=True, null=True)

    def __str__(self):
        return f"Wishlist {self.id} - {self.customer.email}"


class WishlistItem(models.Model):
    wishlist = models.ForeignKey(
        Wishlist, on_delete=models.CASCADE, related_name='items')
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    added_on = models.DateTimeField(auto_now_add=True, null=True)

    def __str__(self):
        return f"{self.product.name}"


class Payment(models.Model):
    order = models.OneToOneField(
        Order, on_delete=models.CASCADE, related_name='payment')
    payment_method = models.CharField(max_length=50)
    payment_status = models.CharField(max_length=20, choices=[(
        'pending', 'Pending'), ('completed', 'Completed'), ('failed', 'Failed')])
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    payment_date = models.DateTimeField(auto_now_add=True, null=True)

    def __str__(self):
        return f"Payment {self.id} for Order {self.order.id}"


class ShippingAddress(models.Model):
    customer = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='shipping_addresses')
    address_line1 = models.CharField(max_length=255)
    address_line2 = models.CharField(max_length=255, blank=True, null=True)
    city = models.CharField(max_length=100)
    state = models.CharField(max_length=100)
    postal_code = models.CharField(max_length=20)
    country = models.CharField(max_length=100)
    created_on = models.DateTimeField(auto_now_add=True, null=True)

    def __str__(self):
        return f"{self.address_line1}, {self.city}"


class Transaction(models.Model):
    order = models.OneToOneField(
        Order, on_delete=models.CASCADE, related_name='transaction')
    transaction_id = models.CharField(max_length=255, unique=True)
    transaction_date = models.DateTimeField(auto_now_add=True, null=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    transaction_status = models.CharField(
        max_length=20, choices=[('success', 'Success'), ('failure', 'Failure')])

    def __str__(self):
        return f"Transaction {self.transaction_id} for Order {self.order.id}"


class Discount(models.Model):
    code = models.CharField(max_length=50, unique=True)
    description = models.TextField(blank=True, null=True)
    discount_amount = models.DecimalField(max_digits=10, decimal_places=2)
    discount_type = models.CharField(max_length=20, choices=[(
        'fixed', 'Fixed Amount'), ('percentage', 'Percentage')])
    valid_from = models.DateTimeField()
    valid_to = models.DateTimeField()
    created_on = models.DateTimeField(auto_now_add=True, null=True)

    def __str__(self):
        return self.code


class OrderTracking(models.Model):
    order = models.OneToOneField(
        Order, on_delete=models.CASCADE, related_name='tracking')
    status = models.CharField(max_length=20)
    updated_on = models.DateTimeField(auto_now=True, null=True)
    remarks = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"Tracking {self.order.id} - {self.status}"


class Notification(models.Model):
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='notifications')
    message = models.TextField()
    is_read = models.BooleanField(default=False)
    created_on = models.DateTimeField(auto_now_add=True, null=True)

    def __str__(self):
        return f"Notification {self.id} for {self.user.email}"
