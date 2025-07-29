# FastAPI JWT Authentication

This project is a simple FastAPI application that demonstrates how to implement JWT (JSON Web Token) authentication. It provides a secure way to protect API endpoints by requiring a valid token for access.

## Why this project?

Understanding authentication is a fundamental aspect of web development. This project serves as a clear and concise example of how to implement token-based authentication in a modern Python web framework like FastAPI. It's a great starting point for anyone looking to secure their APIs.

## What does this project do?

*   **User Authentication:** It provides a `/token` endpoint to authenticate users with a username and password.
*   **JWT Token Generation:** Upon successful authentication, it generates a JWT access token.
*   **Protected Endpoints:** It includes example endpoints (`/users/me` and `/users/me/items`) that are protected and can only be accessed with a valid JWT token.
*   **Password Hashing:** It uses `passlib` with `bcrypt` to securely hash and verify user passwords.
*   **Environment Variable Management:** It uses `python-dotenv` to manage sensitive information like the `SECRET_KEY`.

## How to Use

### 1. Installation

First, clone the repository and install the required dependencies.

```bash
git clone https://github.com/Dreww01/fast-api-authentication.git
cd fast-api-authentication
pip install -r requirements.txt
```

### 2. Configuration

This project uses a `.env` file to manage environment variables. Create a `.env` file in the root of the project directory.

```
SECRET_KEY=your_super_secret_key
```

You can generate a strong secret key using the following command:

```bash
openssl rand -hex 32
```

Replace `your_super_secret_key` with the generated key.

### 3. Running the Application

Once the dependencies are installed and the `.env` file is configured, you can run the application using `uvicorn`.

```bash
uvicorn main:app --reload
```

The application will be running at `http://127.0.0.1:8000`.

### 4. Using the API

You can interact with the API using tools like `curl` or by visiting the interactive API documentation provided by FastAPI at `http://127.0.0.1:8000/docs`.

#### Get an Access Token

To get an access token, you need to send a POST request to the `/token` endpoint with the username and password. The default user is `drew` with the password `drew1234`.

```bash
curl -X POST "http://127.0.0.1:8000/token" \
-H "Content-Type: application/x-www-form-urlencoded" \
-d "username=drew&password=drew1234"
```

You will receive a response similar to this:

```json
{
  "access_token": "your_access_token",
  "token_type": "bearer"
}
```

#### Access Protected Endpoints

Now you can use the `access_token` to access the protected endpoints.

```bash
curl -X GET "http://127.0.0.1:8000/users/me" \
-H "Authorization: Bearer your_access_token"
```

This will return the user's information:

```json
{
  "username": "drew",
  "email": "drew@me.com",
  "full_name": "Drew Andrew",
  "disabled": false
}
