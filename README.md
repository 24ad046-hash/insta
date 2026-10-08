# Instagram Login Page

A responsive Instagram-inspired login and signup page with a Node.js/Express backend.

## Features

- **Responsive Frontend**: Mobile-friendly login/signup interface matching Instagram's design
- **Backend API**: Express.js server with SQLite database
- **Authentication**: JWT-based authentication with bcrypt password hashing
- **Input Validation**: Email, username, and password validation
- **CORS Enabled**: Secure cross-origin requests
- **Password Toggle**: Show/hide password functionality
- **Token Storage**: Auth tokens stored in localStorage

## Setup

### Prerequisites

- Node.js (v14+)
- npm or yarn

### Installation

1. Navigate to the project directory:
   ```bash
   cd insta
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Create a `.env` file:
   ```bash
   cp .env.example .env
   ```

4. Update `.env` with your settings (optional for development)

### Running the Application

#### Start the Backend Server

```bash
npm start
```

The server will run at `http://localhost:5000`

For development with auto-reload:
```bash
npm run dev
```

#### Open the Frontend

Open `index.html` in your browser or serve it with a local server:

```bash
npx http-server
```

Then navigate to `http://localhost:8080`

## API Endpoints

### Sign Up
- **POST** `/api/auth/signup`
- Body:
  ```json
  {
    "username": "john_doe",
    "email": "john@example.com",
    "password": "SecurePass123",
    "fullName": "John Doe"
  }
  ```

### Login
- **POST** `/api/auth/login`
- Body:
  ```json
  {
    "username": "john_doe",
    "password": "SecurePass123"
  }
  ```

### Get User Info
- **GET** `/api/auth/me`
- Headers:
  ```
  Authorization: Bearer <token>
  ```

## Password Requirements

- Minimum 6 characters
- At least one uppercase letter
- At least one number

## Username Requirements

- Minimum 3 characters
- Only letters, numbers, dots, and underscores

## Database

The application uses SQLite3 with a `users` table containing:
- `id` - User ID (primary key)
- `username` - Unique username
- `email` - Unique email address
- `password` - Bcrypt hashed password
- `full_name` - Full name
- `created_at` - Account creation timestamp

## Security Notes

- Change the `JWT_SECRET` in production
- Use HTTPS in production
- Implement rate limiting for production
- Store sensitive environment variables securely
- Never expose the database file in production

## File Structure

```
insta/
├── index.html       # Frontend login page
├── server.js        # Express server & API routes
├── db.js            # SQLite database setup
├── auth.js          # Authentication utilities
├── validation.js    # Input validation
├── package.json     # Dependencies
└── .env             # Environment variables
```

## License

MIT
