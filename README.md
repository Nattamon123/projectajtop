# NetWatch - Network Packet Analyzer

NetWatch is an industrial-grade, real-time network packet analyzer built with modern web technologies. It provides a secure, intuitive dashboard for monitoring network traffic, detecting potential anomalies, and analyzing packet data patterns over time.

## 🌟 Key Features

- **Real-Time Packet Monitoring**: Live network traffic analysis streamed via WebSockets.
- **Protocol Analysis**: Detects unencrypted traffic (HTTP/FTP), DNS queries, and potential port scans.
- **RESTful API Architecture**: Decoupled Express API designed for scalability and maintainability.
- **Secure Authentication**: Role-based access control (Admin/Viewer) using JWT and bcrypt.
- **MongoDB Integration**: Permanent storage for logging packets and user activities.

## 📁 Project Structure

```text
netwatch/
├── .env                # Environment variables configuration
├── package.json        # Project metadata and dependencies
├── server.js           # Express app entry point
├── public/             # Static frontend assets (HTML, JS, CSS)
├── src-css/            # Tailwind CSS source files
├── tests/              # Unit and Integration test folder
└── src/                # Backend Source tree
    ├── db/             # Database connection & seed scripts
    ├── middleware/     # Express authentication & validation middlewares
    ├── models/         # Mongoose DB Schemas
    ├── routes/         # Express API Route controllers
    └── socket/         # Socket.IO real-time communication handlers
```

## 🛠️ Installation Requirements

- [Node.js](https://nodejs.org/en/) (v18.x or higher)
- [MongoDB](https://www.mongodb.com/try/download/community) (Running locally on default port 27017, or a remote URI)

## 🚀 Setup & Installation

1. **Install Dependencies**
   ```bash
   npm install
   ```

2. **Environment Variables**
   Ensure an `.env` file exists in the root directory. You can configure:
   ```env
   PORT=3000
   MONGODB_URI=mongodb://localhost:27017/netwatch
   JWT_SECRET=your_super_secret_jwt_key
   JWT_EXPIRES_IN=8h
   ```

3. **Build Frontend CSS**
   Compiles the Tailwind directives into CSS:
   ```bash
   npm run build:css
   ```

4. **Seed the Database** (Optional but recommended)
   Initializes default users (`admin/admin123` and `viewer/viewer123`):
   ```bash
   npm run seed
   ```
   *Note: Application automatically attempts to seed users on first startup.*

## 🏁 Running the Application

**Development Mode** (With Live Reloading & CSS Watcher):
```bash
npm run dev
```

**Production Mode**:
```bash
npm start
```

Access the dashboard at: `http://localhost:3000`

## 🧪 Testing

The project uses Jest and Supertest. To run unit and integration tests:

```bash
npm test
```
