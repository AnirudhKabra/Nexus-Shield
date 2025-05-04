# 🛡️ Malware Detection Web App

A simple web application to detect if a file is malicious or safe using either a hash code or by uploading the file. The app includes user authentication and a personal dashboard to track scan history.

---

## 🚀 Features

### 🔐 1. Login & Signup
- Users can **register** and **log in** securely.
- Simple and user-friendly authentication pages.

### 📊 2. User Dashboard (Scan History)
- Displays:
  - Total number of scanned files
  - Number of **malicious** and **safe** files
- Interactive charts to visualize:
  - Safe vs Malicious file ratio
  - Scan frequency
- Personalized history based on logged-in user

### 🧪 3. File or Hash Scan Page
- Two options to check a file:
  1. **Upload a file**
  2. **Enter the hash code**
- The system detects if the file/hash is safe or malicious
- Adds the result to user history

---

## 🛠️ Tech Stack

- **Frontend**: HTML, CSS, JavaScript
- **Backend**: Flask (Python)
- **Database**: SQLite


## System Requirements

You must have Python 3.8 or later installed. Earlier versions of python may not compile.    

---

## Steps to Replicate 

1. Fork this repository and create a codespace in GitHub as I showed you in the youtube video OR Clone it locally.
   ```
   git clone git@github.com:AnirudhKabra/final_year_project.git
   cd final_year_project
   ```
   
2. Create a virtualenv and activate it
   ```
   python3 -m venv env && source env/bin/activate
   ```

3. Run the following command in the terminal to install necessary python packages:
   ```
   pip install -r requirements.txt
   ```

4. Run the following command in your terminal to run the app UI:
   ```
   python3 -m app


