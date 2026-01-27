Phishing‑Check (Rule‑Based Flask App)
A simple, privacy‑friendly web app that analyzes pasted messages for common phishing patterns using rule‑based logic only — no AI, no external APIs, and no data storage.
Designed to help everyday users understand why a message looks suspicious and what steps they can take next.

🔧 Features
• 	Rule‑based phishing pattern detection
• 	Sender‑email analysis (TLD checks, impersonation patterns, unusual formatting)
• 	Clear risk levels (Low / Medium / High)
• 	Calm, supportive explanations
• 	Step‑by‑step guidance for everyday users
• 	Optional helper: “How to see the real sender address”
• 	No data stored, logged, or transmitted
• 	Fully local or deployable to the web

🖥️ Run Locally (Windows)
1. Create and activate a virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

2. Install dependencies
pip install -r requirements.txt

3. Start the app
python app.py

Open your browser to:
http://127.0.0.1:5000/

Notes
• 	This project uses only local, rule‑based logic — no AI calls.
• 	The app does not store or log any user messages.
• 	Running locally keeps all pasted content private to your device.

🌐 Deployment (Render)
This app can be deployed to Render as a public web service.
Required files
• app.py	
• requirements.txt	
• templates/ folder
• static/ folder (if used)

Required requirements.txt
Flask>=2.0
gunicorn

(Include python-dotenv only if your code loads environment variables.)
Render configuration
• 	Build Command:
pip install -r requirements.txt
• 	Start Command:
gunicorn app:app
Render will automatically:
• 	install dependencies
• 	launch the production server
• 	provide a public HTTPS URL

🔒 Privacy
This tool does not:
• 	store messages
• 	log user input
• 	send data to external services
• 	use analytics or tracking
Everything is processed in memory and discarded immediately.

🧪 Beta Notice
This is an early version.
Feedback is welcome to improve clarity, accuracy, and user experience.