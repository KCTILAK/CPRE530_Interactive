import streamlit as st

# Define the full content structure
content = {
    "Introduction": {
        "title": "Introduction to Password Security",
        "body": """Passwords are a fundamental component of online security, acting as the first line of defense against 
unauthorized access to personal accounts, sensitive data, and critical systems. However, the increasing sophistication 
of cyberattacks has exposed the weaknesses of poorly created passwords, making it essential to understand their role 
in securing networks and how to create them effectively."""
    },
st.image("C:/Users/91703/OneDrive/Desktop/graph1.png")
    "Lesson 1: Password Strength and Entropy": {
        "title": "Understanding Password Strength and Entropy",
	
        "objectives": [
            "Explain the importance of password security in protecting digital assets.",
            "Define password entropy and describe how it measures strength and complexity.",
            "Identify the factors that increase password entropy: length, character set, and unpredictability.",
            "Calculate password entropy and set minimum entropy thresholds.",
            "Evaluate password strength using password strength meters and distinguish between strong and weak passwords."
        ],
        "body": """Password strength refers to the ability of a password to resist guessing and cracking attempts. A strong 
password is one that is difficult for both humans and computers to guess or crack. The strength of a password is 
determined by several factors, including length, complexity, and unpredictability.

Entropy is a measure of the randomness and uncertainty in a password. In the context of password security, entropy 
quantifies the amount of information or "randomness" contained in a password. The higher the entropy, the stronger 
and more secure the password is considered to be.""",
        "quiz": [
            {
                "question": "Which of the following passwords has the highest entropy?",
                "options": ["password123", "Tr0ub4dor&3", "correcthorsebatterystaple", "qwerty"],
                "answer": 2,
            },
            {
                "question": "What is the minimum recommended entropy for user-generated passwords?",
                "options": ["40 bits", "60 bits", "80 bits", "100 bits"],
                "answer": 2,
            },
        ]
    },
    "Lesson 2: Password Hashing and Secure Storage": {
        "title": "Password Hashing and Secure Storage",
        "objectives": [
            "Describe the risks associated with plaintext password storage and best practices for secure storage.",
            "Explain cryptographic hash functions and their essential properties, including one-way functionality and determinism.",
            "Compare common password hashing algorithms (bcrypt, PBKDF2, scrypt) and their uses.",
            "Demonstrate the role of salts in preventing rainbow table attacks and iteration counts in slowing down cracking attempts.",
            "Implement secure password hashing in web applications.",
            "Assess secure vs. insecure password storage practices."
        ],
        "body": """Password hashing is a cryptographic process that transforms a plain-text password into a fixed-size 
string of characters, known as a hash. The primary purpose of hashing is to ensure that if a password database is 
compromised, the attacker cannot easily retrieve the original passwords.

Key characteristics of cryptographic hash functions include:
1. **One-way**: It is computationally infeasible to reverse a hash and obtain the original password.
2. **Deterministic**: The same password always produces the same hash value.
3. **Unique**: Different passwords should produce different hash values, with a low probability of collisions.
4. **Fixed-size**: Regardless of the input password length, the hash output has a fixed size.""",
        "quiz": [
            {
                "question": "Why is password hashing important?",
                "options": [
                    "To compress passwords and save storage space",
                    "To make passwords easier to remember",
                    "To protect passwords in case of a database breach",
                    "To allow password sharing between users",
                ],
                "answer": 2,
            },
            {
                "question": "Which of the following is NOT a property of a cryptographic hash function?",
                "options": ["One-way", "Deterministic", "Reversible", "Fixed-size output"],
                "answer": 2,
            },
        ]
    },
    "Lesson 3: Defending Against Password Attacks": {
        "title": "Defending Against Password Attacks",
        "objectives": [
            "Identify common password attack vectors, including brute-force attacks, dictionary attacks, and credential stuffing.",
            "Analyze the effectiveness of password complexity requirements in defending against attacks.",
            "Apply NIST guidelines to establish password requirements.",
            "Implement rate limiting and account lockouts to prevent online guessing attacks.",
            "Evaluate the role of password managers in mitigating risks of password reuse.",
            "Develop strategies to defend against various password attack scenarios."
        ],
        "body": """Password attacks are methods used by malicious actors to gain unauthorized access to user accounts 
or data. Common techniques include brute-force attacks, dictionary attacks, and credential stuffing. Understanding 
these techniques helps in implementing stronger defenses against them.

**Brute-force attacks** systematically try all possible password combinations until the correct one is found. The 
effectiveness of this attack depends on the password's length and complexity.

**Dictionary attacks** use precompiled lists of common words and password variations to guess the password. Using 
real words or common patterns makes passwords vulnerable to these attacks.""",
        "quiz": [
            {
                "question": "Which of the following is an example of a brute-force attack?",
                "options": [
                    "Trying common words and phrases from a wordlist",
                    "Systematically attempting all possible password combinations",
                    "Using precomputed hash tables to crack passwords",
                    "Tricking users into revealing their passwords through phishing emails",
                ],
                "answer": 1,
            },
            {
                "question": "True or False: Dictionary attacks are ineffective against passwords that include dictionary words with minor modifications, such as replacing 'a' with '@'.",
                "options": ["True", "False"],
                "answer": 1,
            },
        ]
    },


"Lesson 4: Password Security Best Practices": {
        "title": "Password Security Best Practices",
        "objectives": [
            "Create strong, unique passwords for different accounts using best practices.",
            "Avoid common patterns, such as dates, names, and keyboard sequences, in password creation.",
            "Recognize the risks of reusing passwords across multiple accounts.",
            "Use password managers to generate and securely store complex passwords.",
            "Understand the importance of regular password rotation, especially after breaches."
        ],
        "body": """Throughout this module, we have explored the importance of password strength, secure storage techniques, 
and strategies for defending against common password attacks. In this final lesson, we will consolidate our knowledge 
and discuss best practices for creating and managing strong passwords across multiple accounts. By adhering to these 
guidelines, users can significantly enhance the security of their online presence and protect their sensitive information.""",
        "quiz": [
            {
                "question": "What is the recommended minimum length for a strong password?",
                "options": ["6 characters", "8 characters", "10 characters", "12 characters"],
                "answer": 3,
            },
            {
                "question": "It is acceptable to reuse the same password for multiple accounts as long as it is strong and complex.",
                "options": ["True", "False"],
                "answer": 1,
            },
            {
                "question": "Which of the following is an example of a secure method for sharing passwords when necessary?",
                "options": [
                    "Sending the password via email",
                    "Sharing the password through an instant messaging app",
                    "Using an encrypted password manager",
                    "Writing the password on a piece of paper and handing it over"
                ],
                "answer": 2,
            },
            {
                "question": "How often should you consider changing passwords for critical accounts?",
                "options": [
                    "Every month",
                    "Every 3-6 months",
                    "Once a year",
                    "Never, if the password is strong enough"
                ],
                "answer": 1,
            },
            {
                "question": "Enabling two-factor authentication (2FA) eliminates the need for strong passwords.",
                "options": ["True", "False"],
                "answer": 1,
            },
        ]
    },
"Lesson 5: Introduction to Multi-Factor Authentication (MFA)": {
    "title": "Introduction to Multi-Factor Authentication (MFA)",
    "objectives": [
        "Understand the definition and overview of Multi-Factor Authentication (MFA).",
        "Recognize the three main categories of authentication factors: knowledge, possession, and inherence.",
        "Explain how MFA enhances account security beyond traditional passwords.",
        "Identify real-world examples of MFA implementation in various domains."
    ],
    "body": """In today's digital landscape, where cyber threats are continuously evolving, relying solely on passwords for 
account security is no longer sufficient. Passwords, even when strong and unique, can still be compromised through various 
means such as phishing attacks, data breaches, or social engineering techniques. This is where Multi-Factor Authentication 
(MFA) comes into play, providing an additional layer of protection to safeguard user accounts and sensitive information.

### Definition and Overview of MFA
Multi-Factor Authentication (MFA) is a security process that requires users to provide two or more forms of identification 
to access an account or system. Unlike traditional authentication methods that rely only on a username and password, MFA adds 
one or more additional verification factors, making it significantly more difficult for unauthorized individuals to gain 
access, even if they possess the user's password.

### Authentication Factors
Authentication factors can be classified into three main categories:
1. **Knowledge Factors (Something You Know)**:
   - Passwords, PINs, or security questions are examples of knowledge factors.
   - These factors rely on information that the user knows and provides during the authentication process.
   - While passwords are the most common knowledge factor, they are also the most vulnerable to compromise.
2. **Possession Factors (Something You Have)**:
   - Involve physical objects that the user possesses, such as a smartphone, hardware token, or smart card.
   - Examples include receiving a one-time code via SMS, using a mobile authenticator app, or inserting a smart card into a reader.
3. **Inherence Factors (Something You Are)**:
   - Biometric factors rely on the user's unique physical characteristics for authentication.
   - Common examples include fingerprint scans, facial recognition, or iris scans.
   - Biometric factors are inherently tied to the user and are difficult to replicate or steal.

### Real-World MFA Examples
1. **Online Banking**:
   - Financial institutions require MFA for online banking access.
   - Users may be prompted to enter a one-time code sent via SMS or generated by a mobile app.
2. **Corporate VPNs**:
   - MFA is implemented for secure remote access to corporate networks.
   - Employees use hardware tokens or mobile apps for one-time code generation in addition to login credentials.
3. **Email Accounts**:
   - Major email providers like Google and Microsoft offer MFA to secure user accounts.
   - Users enable MFA to require a second form of verification, such as a code sent to their mobile device or an authenticator app.""",
    "quiz": [
        {
            "question": "What is the primary purpose of Multi-Factor Authentication (MFA)?",
            "options": [
                "To replace passwords altogether",
                "To add an extra layer of security beyond passwords",
                "To make the login process faster and more convenient",
                "To eliminate the need for user authentication"
            ],
            "answer": 1,
        },
        {
            "question": "Which of the following is an example of a knowledge factor in MFA?",
            "options": ["Fingerprint scan", "Security token", "PIN code", "Facial recognition"],
            "answer": 2,
        },
        {
            "question": "True or False: Possession factors in MFA involve physical objects that the user possesses, such as a smartphone or smart card.",
            "options": ["True", "False"],
            "answer": 0,
        },
        {
            "question": "Which of the following is an example of an inherence factor in MFA?",
            "options": ["Password", "SMS-based one-time code", "Iris scan", "Security question"],
            "answer": 2,
        },
        {
            "question": "True or False: MFA is commonly used in online banking to protect sensitive financial information.",
            "options": ["True", "False"],
            "answer": 0,
        },
    ]
},
"Lesson 6: MFA Methods and Technologies": {
    "title": "MFA Methods and Technologies",
    "objectives": [
        "Understand the functionalities, strengths, and weaknesses of different MFA methods.",
        "Analyze the pros and cons of SMS-based OTPs, TOTP authenticator apps, hardware tokens, and biometric authentication.",
        "Explore emerging MFA technologies, such as risk-based authentication and passwordless authentication."
    ],
    "body": """In the previous lesson, we introduced the concept of Multi-Factor Authentication (MFA) and its role in enhancing account security by requiring users to provide multiple forms of identification. We also explored the three main categories of authentication factors: knowledge, possession, and inherence. In this lesson, we will dive deeper into the various MFA methods and technologies available, examining their functionalities, strengths, and weaknesses.

### SMS-Based One-Time Passwords (OTPs)
SMS-based OTPs are a common MFA method that leverages the user's mobile phone as a possession factor. When a user attempts to log in, the system sends a unique, time-sensitive code via SMS to the user's registered mobile number. The user must enter this code along with their username and password to gain access to the account.

#### Pros:
- Widely accessible, as most users have a mobile phone capable of receiving SMS.
- Easy to implement and use, requiring no additional hardware or software.
- Provides an extra layer of security beyond passwords alone.

#### Cons:
- Vulnerable to SIM swapping attacks, where an attacker convinces the mobile carrier to transfer the victim's phone number to a new SIM card.
- SMS messages can be intercepted or delayed, potentially allowing attackers to obtain the OTP.
- Relies on the availability and reliability of the mobile network.

### Time-Based One-Time Password (TOTP) Authenticator Apps
TOTP authenticator apps, such as Google Authenticator and Microsoft Authenticator, generate time-based one-time passwords on the user's smartphone. These apps use a shared secret key, usually provided as a QR code during setup, to generate a unique code that changes every 30-60 seconds.

#### Pros:
- More secure than SMS-based OTPs, as the codes are generated locally on the user's device.
- Does not rely on mobile network availability or risk interception.
- Codes are valid for a short time window, reducing the chances of unauthorized use.

#### Cons:
- Requires the user to have a smartphone and install the authenticator app.
- If the user loses or replaces their phone, they need to re-configure the authenticator app.
- Time synchronization issues between the server and the app can sometimes lead to authentication failures.

### Hardware Tokens and Smart Cards
Hardware tokens and smart cards are physical devices that users possess to prove their identity during the authentication process. These devices can generate one-time passwords, store digital certificates, or communicate with the system via USB, NFC, or Bluetooth.

#### Pros:
- Highly secure, as the cryptographic keys are stored securely on the hardware device.
- Resistant to phishing and malware attacks, as the device is separate from the user's computer.
- Some tokens can function offline, without the need for an internet connection.

#### Cons:
- Requires the distribution and management of physical devices to users.
- Higher implementation and maintenance costs compared to software-based solutions.
- If the user loses the device, they may be temporarily locked out of their account until a replacement is provided.

### Biometric Authentication
Biometric authentication methods rely on the user's unique physical characteristics, such as fingerprints, facial features, or iris patterns, to verify their identity. These methods fall under the inherence factor category.

#### Pros:
- Provides a high level of assurance, as biometric traits are unique to each individual.
- Offers a seamless and convenient user experience, eliminating the need to remember codes or carry devices.
- Difficult for attackers to replicate or steal biometric data.

#### Cons:
- Requires specialized hardware, such as fingerprint scanners or facial recognition cameras.
- Biometric data is sensitive and must be securely stored and protected.
- False positives or false negatives can sometimes occur, leading to authentication errors.

### Emerging MFA Methods
In addition to the established MFA methods discussed above, there are several emerging technologies that aim to enhance security and user experience:

1. **Risk-Based Authentication**: This method uses machine learning algorithms to analyze user behavior, device attributes, and contextual factors to determine the risk level of each login attempt. Additional authentication steps may be required for high-risk logins.
2. **Passwordless Authentication**: This approach eliminates the need for passwords altogether, relying solely on possession factors (e.g., security keys) or inherence factors (e.g., biometrics) for authentication.
3. **Continuous Authentication**: Instead of a one-time verification, continuous authentication methods monitor user behavior and interactions throughout the session, using techniques like keystroke dynamics or mouse movement analysis to ensure the user's ongoing legitimacy.""",
    "quiz": [
        {
            "question": "Which MFA method uses the user's mobile phone to receive a unique code via SMS?",
            "options": ["TOTP authenticator apps", "Hardware tokens", "SMS-based OTPs", "Biometric authentication"],
            "answer": 2,
        },
        {
            "question": "True or False: TOTP authenticator apps generate one-time passwords that are valid for an extended period, typically several hours.",
            "options": ["True", "False"],
            "answer": 1,
        },
        {
            "question": "What is a key advantage of hardware tokens compared to SMS-based OTPs?",
            "options": [
                "Hardware tokens are more widely accessible to users.",
                "Hardware tokens are less expensive to implement.",
                "Hardware tokens are resistant to phishing and malware attacks.",
                "Hardware tokens offer a more convenient user experience."
            ],
            "answer": 2,
        },
        {
            "question": "Which of the following is an example of biometric authentication?",
            "options": ["Entering a password", "Using a fingerprint scanner", "Receiving an SMS code", "Inserting a smart card"],
            "answer": 1,
        },
        {
            "question": "True or False: Risk-based authentication relies solely on inherence factors to determine the risk level of a login attempt.",
            "options": ["True", "False"],
            "answer": 1,
        },
    ]
},
"Lesson 7: Implementing MFA on Common Platforms": {
    "title": "Implementing MFA on Common Platforms",
    "objectives": [
        "Learn step-by-step instructions for enabling MFA on popular platforms like Google, Microsoft, and social media.",
        "Understand best practices for managing MFA within an organization.",
        "Develop skills to monitor and respond to MFA-related incidents."
    ],
    "body": """In the previous lessons, we explored the concept of Multi-Factor Authentication (MFA), its various methods, and the technologies involved. We discussed the importance of MFA in enhancing account security and protecting against unauthorized access. In this lesson, we will focus on the practical implementation of MFA on common online platforms, providing step-by-step guides for enabling MFA and discussing best practices for managing MFA in an organization.

### Enabling MFA on Popular Platforms
Many online platforms and services now offer MFA options to help users secure their accounts. Below are step-by-step guides for enabling MFA on some of the most widely used platforms:

#### 1. Google/Gmail Accounts:
- Log in to your Google account and navigate to the "Security" settings.
- Under the "Signing in to Google" section, click on "2-Step Verification."
- Follow the prompts to set up MFA using your preferred method (e.g., Google Authenticator app, SMS, or backup codes).
- Once MFA is enabled, you will be required to provide a second form of authentication whenever you log in to your Google account.

#### 2. Microsoft Accounts and Office 365:
- Sign in to your Microsoft account and go to the "Security" settings.
- Select "More security options" and then choose "Set up two-step verification."
- Follow the instructions to configure MFA using the Microsoft Authenticator app, SMS, or alternate email address.
- After MFA is set up, you will need to provide the additional authentication factor when logging in to your Microsoft account or Office 365 applications.

#### 3. Social Media Platforms (Facebook, Twitter, LinkedIn):
- **Facebook**:
  - Go to the "Security and Login" settings in your Facebook account.
  - Under the "Two-Factor Authentication" section, click on "Edit."
  - Choose your preferred MFA method (e.g., authentication app, SMS, or hardware token) and follow the setup instructions.
- **Twitter**:
  - Navigate to the "Security and account access" settings in your Twitter account.
  - Select "Security" and then "Two-factor authentication."
  - Choose your desired MFA method (e.g., authentication app, SMS, or hardware token) and complete the setup process.
- **LinkedIn**:
  - Access the "Account" settings in your LinkedIn profile.
  - Click on "Two-step verification" under the "Login and security" section.
  - Select your preferred MFA method (e.g., authentication app or SMS) and follow the prompts to enable MFA.

#### 4. Online Banking and Financial Services:
- Most major banks and financial institutions now offer MFA options to protect sensitive customer information.
- Log in to your online banking portal and look for security settings or options related to two-factor authentication or enhanced security.
- Follow the provided instructions to set up MFA using methods such as SMS, email, or dedicated authenticator apps.
- Some banks may require you to contact customer support or visit a branch to enable MFA for your account.

### Best Practices for Managing MFA
Implementing MFA is an essential step towards enhancing account security, but it is equally important to manage MFA effectively within an organization. Here are some best practices to consider:

1. **User Education and Awareness**:
   - Provide training and resources to help users understand the importance of MFA and how to set it up properly.
   - Encourage users to enable MFA on all their accounts, not just work-related ones.
   - Regularly remind users to keep their MFA settings up to date and to report any suspicious activity.

2. **Consistent Enforcement**:
   - Establish policies that require MFA for all user accounts, especially those with access to sensitive data or systems.
   - Enforce MFA consistently across the organization, without exceptions for specific users or departments.
   - Regularly audit and review MFA settings to ensure compliance and identify any gaps.

3. **Secure Backup and Recovery**:
   - Encourage users to set up secure backup methods, such as backup codes or alternate authentication factors, in case their primary MFA method is lost or unavailable.
   - Establish clear procedures for MFA recovery, including identity verification steps and secure channels for communication.
   - Regularly test and update backup and recovery processes to ensure their effectiveness.

4. **Monitoring and Incident Response**:
   - Implement monitoring systems to detect and alert on suspicious MFA activity, such as multiple failed authentication attempts or logins from unusual locations.
   - Develop an incident response plan that outlines the steps to be taken in case of an MFA-related security breach.
   - Regularly review and update monitoring and incident response procedures based on new threats and best practices.""",
    "quiz": [
        {
            "question": "What is the first step in enabling MFA for a Google/Gmail account?",
            "options": [
                "Navigating to the 'Security' settings",
                "Setting up a backup email address",
                "Installing the Google Authenticator app",
                "Contacting Google customer support"
            ],
            "answer": 0,
        },
        {
            "question": "True or False: Enabling MFA on social media platforms like Facebook and Twitter typically involves choosing a preferred MFA method and following the setup instructions.",
            "options": ["True", "False"],
            "answer": 0,
        },
        {
            "question": "Which of the following is an example of a best practice for managing MFA in an organization?",
            "options": [
                "Providing MFA training only to users with access to sensitive data",
                "Allowing exceptions to MFA policies for specific departments",
                "Regularly auditing and reviewing MFA settings for compliance",
                "Encouraging users to share their MFA backup codes with colleagues"
            ],
            "answer": 2,
        },
        {
            "question": "What should an organization do if a user reports a lost or stolen MFA device?",
            "options": [
                "Disable MFA for the user's account until a replacement device is obtained",
                "Initiate the MFA recovery process, including identity verification steps",
                "Provide the user with another user's MFA device as a temporary solution",
                "Require the user to create a new account with a different username"
            ],
            "answer": 1,
        },
        {
            "question": "True or False: Implementing MFA eliminates the need for monitoring and incident response procedures related to authentication security.",
            "options": ["True", "False"],
            "answer": 1,
        }
    ]
},
"Lesson 8: MFA Security Considerations and Limitations": {
    "title": "MFA Security Considerations and Limitations",
    "objectives": [
        "Understand the vulnerabilities and attack vectors associated with MFA.",
        "Learn strategies to secure the authentication ecosystem beyond MFA.",
        "Explore methods to balance security and usability in MFA implementation.",
        "Discuss the privacy considerations of collecting and storing MFA-related data."
    ],
    "body": """In the previous lessons, we explored the concept of Multi-Factor Authentication (MFA), its various methods, and the practical implementation of MFA on common online platforms. While MFA provides a significant security enhancement over traditional single-factor authentication, it is important to understand that MFA is not a silver bullet solution. In this lesson, we will discuss the security considerations and limitations of MFA, potential vulnerabilities, and strategies for mitigating these risks.

### Potential Vulnerabilities and Attack Vectors
#### 1. Social Engineering and Phishing:
- Attackers may trick users into revealing their MFA codes or passwords through phishing emails or fake login pages.
- Example: An attacker sends a phishing email claiming to be from a legitimate service, prompting the user to enter their MFA code on a fake website.
- **Mitigation**: Educate users to identify and report phishing attempts.

#### 2. Session Hijacking and Man-in-the-Middle Attacks:
- Attackers intercept user sessions after successful MFA authentication or use MitM attacks to steal MFA codes.
- **Mitigation**: Use HTTPS with proper certificate validation to secure communication.

#### 3. SMS-Based MFA Vulnerabilities:
- Attackers exploit SS7 vulnerabilities or use SIM swapping attacks to intercept SMS messages.
- **Mitigation**: Encourage users to adopt more secure MFA methods like authenticator apps or hardware tokens.

### Securing the Authentication Ecosystem
#### 1. Protecting MFA Secrets and Tokens:
- Securely generate, store, and transmit MFA secrets.
- Educate users to safeguard MFA devices and report suspicious activity.

#### 2. Secure Enrollment and Recovery Processes:
- Use identity verification during MFA setup and recovery.
- Establish encrypted communication channels for MFA-related processes.

#### 3. Regular Security Audits and Updates:
- Test MFA implementations for vulnerabilities.
- Keep MFA systems updated and monitor logs for potential security incidents.

### Balancing Security and Usability
#### 1. User Experience and Workflow:
- Minimize friction by offering multiple MFA options.
- Integrate MFA seamlessly into workflows.

#### 2. Accessibility and Inclusivity:
- Ensure MFA methods are accessible to users with disabilities.
- Provide support for users with varying technical abilities.

#### 3. Performance and Reliability:
- Design MFA systems for high availability and performance.
- Use backup mechanisms to maintain functionality during outages.

### Privacy Considerations
#### 1. Data Collection and Storage:
- Clearly communicate data collection practices and obtain user consent.
- Protect MFA-related data with encryption and access controls.

#### 2. Data Retention and Deletion:
- Define retention policies and allow users to request data deletion when no longer needed.

#### 3. Third-Party Integrations:
- Evaluate third-party MFA providers for privacy compliance.
- Implement data protection agreements with providers.

### Conclusion
MFA enhances security but is not a perfect solution. It requires continuous monitoring, evaluation, and improvement. By understanding its limitations and addressing vulnerabilities, organizations can protect user accounts and sensitive data effectively.""",
    "quiz": [
        {
            "question": "Which of the following is an example of a social engineering attack related to MFA?",
            "options": [
                "Sending a phishing email that prompts the user to enter their MFA code on a fake website",
                "Intercepting a user's session after successful MFA authentication",
                "Exploiting SS7 vulnerabilities to intercept SMS messages containing MFA codes",
                "Conducting a brute-force attack to guess a user's MFA code"
            ],
            "answer": 0,
        },
        {
            "question": "True or False: Implementing HTTPS with proper certificate validation can help mitigate the risk of session hijacking and Man-in-the-Middle attacks.",
            "options": ["True", "False"],
            "answer": 0,
        },
        {
            "question": "What is the main risk associated with SMS-based MFA?",
            "options": [
                "SMS messages can be easily intercepted or redirected by attackers",
                "SMS-based MFA is not widely supported by online platforms",
                "SMS messages are not encrypted, making them vulnerable to eavesdropping",
                "SMS-based MFA is more expensive to implement compared to other methods"
            ],
            "answer": 0,
        },
        {
            "question": "Which of the following is an important consideration when balancing security and usability in MFA implementation?",
            "options": [
                "Ensuring that MFA methods are accessible to users with disabilities",
                "Minimizing the number of MFA options available to users",
                "Requiring users to set up MFA on all their devices simultaneously",
                "Storing MFA-related user data indefinitely for future reference"
            ],
            "answer": 0,
        },
        {
            "question": "True or False: Organizations are not required to obtain user consent for collecting and storing MFA-related personal information, as it is necessary for security purposes.",
            "options": ["True", "False"],
            "answer": 1,
        }
    ]
}






}

# Streamlit App
st.title("Interactive Password Security and MFA Educational App")

# Sidebar Navigation
section = st.sidebar.radio("Select a Section", list(content.keys()))

# Display the selected content
st.header(content[section]["title"])
st.write(content[section].get("body", ""))

# Display Objectives
if "objectives" in content[section]:
    st.subheader("Learning Objectives")
    for obj in content[section]["objectives"]:
        st.write(f"- {obj}")

# Display Quiz
if "quiz" in content[section]:
    st.subheader("Quiz")
    for i, quiz in enumerate(content[section]["quiz"]):
        st.write(f"Q{i+1}: {quiz['question']}")
        user_answer = st.radio(f"Select an answer for Q{i+1}", quiz["options"], key=f"quiz-{i}")
        if st.button(f"Submit Answer for Q{i+1}", key=f"submit-{i}"):
            if quiz["options"].index(user_answer) == quiz["answer"]:
                st.success("Correct!")
            else:
                st.error("Incorrect, try again!")


import streamlit as st
import random
import string
import re
from math import log
import time


# Function to calculate password entropy
def calculate_entropy(password):
    """
    Calculates the entropy of a password based on its length and character set.
    """
    length = len(password)
    char_set_size = 0

    # Check for the presence of different character types and update the character set size accordingly
    if re.search(r'[a-z]', password):
        char_set_size += 26
    if re.search(r'[A-Z]', password):
        char_set_size += 26
    if re.search(r'[0-9]', password):
        char_set_size += 10
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        char_set_size += 32

    if char_set_size > 0:
        entropy = length * (log(char_set_size, 2))
    else:
        entropy = 0  # If no characters present, entropy is zero
    return entropy


# Password Strength Checker App
def password_strength_checker():
    st.subheader("Password Strength Checker")
    st.write("Evaluate your password's strength and get recommendations for improvement.")

    # Input for password
    password = st.text_input("Enter your password", type="password")

    if password:
        # Calculate password entropy
        entropy = calculate_entropy(password)
        st.write("Password Entropy:", round(entropy, 2), "bits")

        # Assess password strength
        if entropy < 28:
            strength = "Very Weak"
            color = "red"
        elif entropy < 36:
            strength = "Weak"
            color = "orange"
        elif entropy < 60:
            strength = "Moderate"
            color = "yellow"
        elif entropy < 128:
            strength = "Strong"
            color = "green"
        else:
            strength = "Very Strong"
            color = "darkgreen"

        # Show password strength
        st.markdown(f'<p style="color:{color};">Password Strength: {strength}</p>', unsafe_allow_html=True)

        # Provide recommendations
        if strength in ["Very Weak", "Weak", "Moderate"]:
            st.subheader("Recommendations to Improve Your Password:")
            if len(password) < 12:
                st.write("- Increase password length to at least 12 characters.")
            if not re.search(r'[A-Z]', password):
                st.write("- Include uppercase letters.")
            if not re.search(r'[a-z]', password):
                st.write("- Include lowercase letters.")
            if not re.search(r'[0-9]', password):
                st.write("- Add numbers.")
            if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
                st.write("- Use special characters.")
            st.write("- Avoid common patterns like '123', 'abc', or predictable phrases.")

    else:
        st.write("Enter a password to analyze its strength.")


# Function to generate random codes for MFA
def generate_code(length=6):
    characters = string.ascii_uppercase + string.digits
    return ''.join(random.choice(characters) for _ in range(length))


# Multi-Factor Authentication Simulation App
def mfa_simulation():
    st.subheader("Multi-Factor Authentication (MFA) Simulation")
    st.write("Experience the process of setting up and using different MFA methods.")

    # Selection for MFA method
    mfa_method = st.radio("Choose an MFA Method:", ["SMS", "Authenticator App", "Hardware Token"])

    # MFA Simulation based on the chosen method
    if mfa_method == "SMS":
        simulate_sms_mfa()
    elif mfa_method == "Authenticator App":
        simulate_authenticator_app_mfa()
    elif mfa_method == "Hardware Token":
        simulate_hardware_token_mfa()


# SMS-Based MFA Simulation
def simulate_sms_mfa():
    st.write("Simulate SMS-based Multi-Factor Authentication.")
    phone_number = st.text_input("Enter your phone number")
    if phone_number:
        code = generate_code()
        st.write(f"Sending verification code to {phone_number}...")
        time.sleep(2)
        st.success(f"Verification code sent: {code}")
        user_input = st.text_input("Enter the received code:")
        if user_input == code:
            st.success("Authentication successful!")
        else:
            st.error("Authentication failed. Try again.")


# Authenticator App MFA Simulation
def simulate_authenticator_app_mfa():
    st.write("Simulate Authenticator App-based MFA.")
    code = generate_code()
    st.write("Open your authenticator app and enter the code below:")
    st.success(code)
    user_input = st.text_input("Enter the code from the app:")
    if user_input == code:
        st.success("Authentication successful!")
    else:
        st.error("Authentication failed. Try again.")


# Hardware Token MFA Simulation
def simulate_hardware_token_mfa():
    st.write("Simulate Hardware Token-based MFA.")
    code = generate_code()
    st.write("Connect your hardware token to your device and press the button to generate a code.")
    time.sleep(2)
    st.success(f"Generated Code: {code}")
    user_input = st.text_input("Enter the displayed code:")
    if user_input == code:
        st.success("Authentication successful!")
    else:
        st.error("Authentication failed. Try again.")


# Main App Layout
def main():
    st.title("Interactive Tools for Security Education")
    st.sidebar.title("Choose a Tool")

    # Tool selection
    app_mode = st.sidebar.radio("Select an interactive feature:", 
                                ["Password Strength Checker", "Multi-Factor Authentication Simulation"])

    # Render the selected tool
    if app_mode == "Password Strength Checker":
        password_strength_checker()
    elif app_mode == "Multi-Factor Authentication Simulation":
        mfa_simulation()


if __name__ == "__main__":
    main()

