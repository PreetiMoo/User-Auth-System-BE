Find the Postman collection and environment in the repository

Features
- User Registration with username, email and password validation
- User Login with JWT authentication
- Password Reset with old password validation
- Protected routes using JWT
- Uses MongoDB Atlas for cloud database
- Deployed on Render

Tech Stack
- Node.js
- Express.js
- MongoDB Atlas
- Mongoose
- JWT (JSON Web Token)
- bcrypt.js for password hashing

Installation

1️. git clone https://github.com/PreetiMoo/User-Auth-System-BE.git
2. cd User-Auth-System-BE
3. npm install
4. Create a `.env` file in the root directory and add the following variables:
PORT=5000
MONGO_URI=your-mongodb-atlas-connection-string
JWT_SECRET=your-secret-key

5. npm start
The API will be running on `http://localhost:5000`



API Endpoints

1️. Register User
**Endpoint:** `POST /api/auth/register`
**Body:**
{
  "username": "JohnDoe",
  "email": "john@example.com",
  "password": "P@ssword1"
}

**Response:**
{
  "message": "User registered successfully"
}


2️. Login User
**Endpoint:** `POST /api/auth/login`
**Body:**
{
  "email": "john@example.com",
  "password": "P@ssword1"
}

**Response:**
{
  "message": "Login successful",
  "accessToken": "your-jwt-token"
}


3️. Reset Password (Protected Route)
**Endpoint:** `PUT /api/auth/reset-password`
**Headers:** `{ Authorization: 'Bearer your-jwt-token' }`
**Body:**
{
  "oldPassword": "P@ssword1",
  "newPassword": "NewP@ssword2",
  "confirmPassword": "NewP@ssword2"
}

**Response:**
{
  "message": "Password reset successful"
}

