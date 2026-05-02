# CyberShieldAI: Behavioral Intrusion Detection System (IDS)

## Project Overview
> **[📄 Download / View the Presentation PDF](docs/CyberShield_AI_Styled_Presentation.pdf)**

CyberShieldAI is a web-based Intrusion Detection System (IDS) designed to detect anomalous and potentially malicious network behavior using an unsupervised machine learning approach. The system is built using a Flask backend and provides a secure, multi-user dashboard for monitoring, analysis, and reporting.

The project focuses on identifying unknown (zero-day) threats and improving transparency using Explainable AI (XAI), making it useful for cybersecurity analysis and academic demonstration.

---

## Core Features

- Live Threat Detection  
  Provides real-time monitoring of network activity and generates alerts based on severity levels such as Low, Medium, and High.

- Dual-Mode Data Input  
  Supports both manual packet entry for testing and CSV file upload for batch processing.

- Interactive Analytics Dashboard  
  Displays network statistics including total packets, normal traffic, detected threats, and visual graphs.

- Explainable AI (XAI)  
  Provides clear, human-readable explanations for each detected anomaly.

- Automated Report Generation  
  Generates structured PDF reports for analysis and documentation.

---

## Machine Learning Model

- Algorithm Used  
  Isolation Forest (Unsupervised Learning)

- Working Principle  
  Detects anomalies by identifying data points that differ significantly from normal patterns.

- Zero-Day Detection  
  Does not require labeled data, allowing detection of unknown threats.

- Performance  
  Achieved approximately 99% accuracy on synthetic dataset during testing.

- Scalability  
  Efficient for handling large-scale network data.

---

## Security and Authentication

- User Registration and Login  
  Secure authentication system for user access.

- Password Security  
  Passwords are hashed using Werkzeug security (no plain-text storage).

- Two-Factor Authentication (2FA)  
  Implemented using PyOTP with support for Google Authenticator.

- Session Management  
  Protected routes using Flask login system to prevent unauthorized access.

---

## System Modules

- Authentication Module  
  Handles user registration, login, and 2FA verification.

- Detection Engine  
  Processes manual input and CSV data to detect anomalies.

- Dashboard Module  
  Displays real-time analytics and system statistics.

- Reporting Module  
  Generates downloadable PDF reports.

---

## Setup and Installation

### 1. Prerequisites
- Python 3.8 or higher installed

---

### 2. Clone the Repository
```bash
git clone https://github.com/Manisha2006-7/cybershield-ai.git
cd cybershield-ai
```

---

### 3. Create a Virtual Environment (Recommended)

```bash
# On Windows
python -m venv venv
venv\Scripts\activate

# On macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

---

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

---

### 5. Train the Machine Learning Model

```bash
python train_model.py
```

This step generates synthetic data, trains the Isolation Forest model, and saves the trained model files required for prediction.

---

### 6. Run the Application

```bash
python app.py
```

Open your browser and navigate to:

http://127.0.0.1:5000

---

## Technology Stack

Backend:
- Python
- Flask
- Flask-SQLAlchemy

Machine Learning:
- Scikit-learn
- Pandas
- NumPy

Frontend:
- HTML5
- CSS3
- JavaScript
- Chart.js

Security:
- Werkzeug Security
- PyOTP (2FA)
- QRCode

---

## Future Enhancements

- Integration with real-time network traffic
- Implementation of deep learning models
- Cloud deployment (AWS / Azure)
- Mobile application interface

---

## Conclusion

CyberShieldAI demonstrates how machine learning can be integrated with web technologies to build an intelligent intrusion detection system. It provides real-time monitoring, explainable results, and a secure architecture, making it suitable for both academic projects and real-world cybersecurity applications.

---

Developed as a BTech Computer Science Engineering Mini Project.
