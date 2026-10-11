# ScamShield Bharat

A student-built, privacy-conscious starter website for digital safety and cyber-fraud awareness. It helps users look for common warning signs in suspicious messages and URLs, learn cyber-safety habits, and find official reporting guidance.

## Features

- Rule-based suspicious-message screening.
- Basic URL structure checks without visiting the submitted URL.
- English, Tamil, and Hindi interface.
- Interactive cyber-safety quiz.
- India-specific fraud response guidance, including 1930 and the official cybercrime portal.
- No database: submitted content is analyzed in memory by this starter app.

## Technology stack

- Python 3
- Flask
- HTML5
- CSS3
- Vanilla JavaScript

## Setup (Ubuntu / WSL / Linux)

1. Install Python and Git:

   ```bash
   sudo apt update
   sudo apt install python3 python3-venv python3-pip git -y
   ```

2. Open this project directory and create a virtual environment:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Start the local development server:

   ```bash
   python app.py
   ```

5. Open `http://127.0.0.1:5000` in your browser.

Stop the server with `Ctrl+C`.

## API endpoints

### `POST /api/analyze/message`

Example JSON:

```json
{"message":"Your bank account is blocked. Verify now and share your OTP."}
```

### `POST /api/analyze/url`

Example JSON:

```json
{"url":"http://bit.ly/example"}
```

The URL checker does not open or fetch the submitted address.

## Sample test cases

| Input | Expected behaviour |
|---|---|
| "Your account is blocked. Verify now and share OTP." | High-risk warning with urgency and credential findings |
| "Congratulations, claim prize; pay processing fee." | Medium/high warning depending on detected phrases |
| "Meeting moved to 3 PM." | Low indicator; still not a safety guarantee |
| `http://bit.ly/example` | Warning for non-HTTPS and URL shortener |
| `https://example.com` | May show low indicator; not a reputation or malware check |
| Empty message or URL | Validation error |

## Important limitations

- This is a heuristic, rule-based educational prototype, not a trained AI model.
- The risk label is not a probability and cannot guarantee that content is safe or malicious.
- URL checks inspect only the entered URL's structure; they do not check domain reputation, certificates, page content, or malware.
- Do not submit real passwords, OTPs, personal information, or sensitive messages.
- For real deployment, add security review, abuse protection, accessibility testing, verified translations, and reliable threat-intelligence sources.

## Architecture

Browser (HTML/CSS/JavaScript) → Flask JSON API → in-memory rule-based message/URL checks → JSON result displayed in browser.

## License

MIT. See `LICENSE`.
