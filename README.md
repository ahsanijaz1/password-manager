# Secure Password Manager
    A simple and secure password manager built with python that allows users to register with a master password, store, and retrieve credentials. Other features are also included such as OTP verification and password generator, all complimented with a clean and responsive GUI.



# Setup Instructions

1. Clone the repository 

        git clone
        https://github.com/ahsanijaz1/password-manager.git

2. Navigate into the project directory
        cd password-manager

3. Create and activate virtual environment (venv)
        python -m venv venv
        venv\Scripts\activate #for windows
        source venv/bin/activate #for Linux/Mac

4. install dependencies 
        pip install -r requirements.txt #to install cryptography


5. Run using command:
        python -m ui.gui

        #when finished
        deactivate


    # Note: If youre using Linux and encounter issues with GUI, make sure tkinter is installed

# Features
    - User registeration
    - Master password validation
    - User login
    - Credentials (Username, website, password) storage
    - Retrieval of stored credentials
    - Credentials can be edited and deleted
    - Password encryption and hashing
    - Strong password generator
    - Email based OTP verification for 2FA


# Limitations
    - OTP currently only works with Gmail email addresses
    - No cloud storage or device sync available in the system due to local storage




# Dummy data
    email: ijazahsan16@gmail.com    
    master password: Ahsan123+

    Note: you will not be able to view stored passwords using this login as it requires email based OTP verification. However, all other functionalities such as login, Adding, Editing and Deleting credentials still work.