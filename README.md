# Shamo Backend – Shoe Store REST API

REST API for **Shamo**, a shoe store mobile app. It serves products and categories, handles user registration and login with token authentication, and records checkout transactions. Built with **Laravel 8**, **Jetstream** and **Sanctum**.

The Flutter client is in [NoviIndraF/shamo_apps](https://github.com/NoviIndraF/shamo_apps).

## Features

- Product list with filters (name, description, tags, price range, category) and pagination.
- Product categories, optionally with their products.
- Register, login and logout with Sanctum bearer tokens.
- Fetch and update the user profile.
- Checkout: create a transaction with its items, address, total and shipping price.
- Transaction history per user, filterable by status.
- Every response uses the same JSON envelope (`meta` + `data`) from `App\Helpers\ResponseFormatter`.

## API

Base URL: `http://127.0.0.1:8000/api`

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/products` | – | List products. Query: `id`, `limit`, `name`, `description`, `tags`, `price_from`, `price_to`, `categories` |
| GET | `/categories` | – | List categories. Query: `id`, `limit`, `name`, `show_product` |
| POST | `/register` | – | Body: `name`, `username`, `email`, `phone`, `password` |
| POST | `/login` | – | Body: `email`, `password`. Returns `access_token` |
| GET | `/user` | Bearer | Current user |
| POST | `/user` | Bearer | Update profile |
| POST | `/logout` | Bearer | Revoke the current token |
| GET | `/transaction` | Bearer | User transactions. Query: `id`, `limit`, `status` |
| POST | `/checkout` | Bearer | Body: `address`, `items[]` (`id`, `quantity`), `total_price`, `shipping_price`, `status` |

Transaction `status` is one of `PENDING`, `SUCCESS`, `CANCELED`, `FAILED`, `SHIPPING`, `SHIPPED`.

Example response:

```json
{
  "meta": { "code": 200, "status": "success", "message": "Data produk berhasil diambil" },
  "data": { "current_page": 1, "data": [ { "id": 1, "name": "...", "price": 58.6, "category": { "id": 1, "name": "..." } } ] }
}
```

## Data model

```
users              + username, phone, roles (USER by default)
product_categories  id, name
products            id, name, price, description, tags, categories_id
product_galleries   id, products_id, url
transactions        id, users_id, address, total_price, shipping_price, status, payment (MANUAL)
transaction_items   id, users_id, products_id, transactions_id, quantity
```

## Tech stack

- Laravel 8, PHP 7.3+ / 8.0
- Laravel Jetstream (Livewire) and Fortify for the web login, Laravel Sanctum for API tokens
- MySQL
- `yajra/laravel-datatables-oracle`

## Getting started

Requirements: PHP 7.3–8.1, Composer, Node.js (for the Jetstream assets), MySQL.

```bash
composer install
cp .env.example .env          # set DB_DATABASE (default: shamo_backend), DB_USERNAME, DB_PASSWORD
php artisan key:generate
php artisan migrate
npm install && npm run dev
php artisan serve
```

The API is then available at http://127.0.0.1:8000/api. Products and categories are added directly in the database (there is no admin panel yet).
