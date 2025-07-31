# Lessons Learned

# Project Scope
- This was my first full-stack project, built from scratch using Flask and Docker.

- Initially developed and tested locally in Ubuntu, I later transitioned the app to Docker to make it easier to deploy, isolate dependencies, and ensure consistent behavior.

- My goal was to create a practical, real-world tool for managing and analyzing Nmap scans with multiple features relevant to the usage of nmap scans.

- I focused on making the system modular, secure, and user-friendly, with clear documentation and a clean project structure.


# Challenges
Parsing Nmap XML
1. Extracting useful data from Nmap’s complex XML output took trial and error, especially when mapping host and port details reliably.

2. Storing data in SQLite
Designing a clean schema for scans, ports, tags, and relationships helped me understand how relational databases work in practice.

3. Connecting backend to frontend
As a beginner, tying Flask routes to logic and showing dynamic data in Jinja templates was a major learning curve — but it taught me how full-stack apps really come together.

4. Starting with weak structure
I began with messy code and minimal planning. Refactoring and modularizing over time taught me the value of clean architecture.

5. Learning logging and debugging
I built a custom logging system that helped with development and production debugging. Making logs readable and persistent across features was key.

6. Using GitHub for the first time
Managing commits, cleaning history, and learning .gitignore taught me real-world version control — not just saving code, but sharing it responsibly.

7. Building independently, without a full tutorial
This project was built from scratch without step-by-step guides. I had to figure things out on my own without a concise answer for my issues, which forced deeper learning and problem solving.

8. Transitioning to Docker
Once development was stable, I migrated everything into Docker to make the app easier to run and deploy. This included learning Dockerfiles, volumes, permissions, and docker-compose.


## Security Decisions
1. Root-owned logs and database
To prevent the app from tampering with its own logs or database, I used root ownership for key files like nmap_results.db and logs/nmap_dashboard.log.

2. Environment variables for secrets
Sensitive settings like the Flask SECRET_KEY are never hardcoded. The app loads them from a .env file, which is excluded from Git and documented in .env.example.

3. No public exposure
The app is meant for trusted networks only. I’ve added clear warnings in the README to avoid exposing it to the internet without further hardening.

4. Minimal attack surface
The container only installs necessary dependencies (Nmap, Flask, SQLite, etc.), keeping the image lightweight and reducing risk.o public exposure
The app is meant for trusted networks only. I’ve added clear warnings in the README to avoid exposing it to the internet without further hardening.

5. Minimal attack surface
The container only installs necessary dependencies (Nmap, Flask, SQLite, etc.), keeping the image lightweight and reducing risk.

## Development Skills Learned
1. Flask Web Development
Built a modular Flask app with routes, templates (Jinja2), and reusable logic.

2. Frontend + Backend Integration
Learned how to pass data from Python routes to HTML templates and render it cleanly in the UI.

3. Dockerization
Transitioned the project to Docker for portability. Built custom images, used docker-compose, and configured host networking for Nmap support.

4. Logging and Debugging
Implemented structured logging across different modules to aid in both debugging and user-facing features.

5. Version Control with Git & GitHub
Gained real experience with commits, .gitignore, branching, and keeping a public repo clean and professional.

6. Documentation and Dev Setup
Wrote a detailed, user-friendly README with full setup and Docker instructions
 
# Things I'd Improve Next Time
1. Use Blueprints and Better Structure from the Start
I learned the importance of starting with a clean architecture. In future projects, I’d design the folder and module layout more carefully from the beginning.

2. Improve UI/UX Design
While functional, the interface is basic. Next time, I’d focus more on layout, responsiveness, and polish.

3. Handle User Permissions and Auth
Right now, the app assumes trusted use. Adding user accounts and access control would be a big next step.

4. Streamline Development Workflow
I want to improve how I plan and build features — aiming for faster, cleaner, and more maintainable development.

5. Build More Complete Features
In this project, I focused on core functionality. Going forward, I’d aim to fully flesh out features with real usability in mind, not just minimum viable versions.

## Final Takeaway
Working on this project gave me hands-on experience with building something practical using Python. I started with a simple idea and kept improving it while learning how to connect code, organize logic, and solve problems as they came up. Tools like Flask, Docker, and AI guidance helped me turn it into a full-featured network scanner dashboard that I can actually use. This project serves as great precursor to the tools and utilites I can create in the future with python.


