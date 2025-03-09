import streamlit as st
import re
import random
import string
from typing import Tuple, List

# Add common weak passwords list
COMMON_PASSWORDS = {
    'password123', 'qwerty123', '12345678', 'abc123', 'password', 
    'admin123', '123456789', 'letmein', 'welcome', 'monkey123',
    'football', 'dragon123', 'baseball', 'sunshine', 'superman'
}

def generate_strong_password(length: int = 16) -> str:
    """
    Generate a strong random password
    
    Args:
        length (int): Length of password to generate
        
    Returns:
        str: Generated password
    """
    # Define character sets
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    special = "!@#$%^&*"
    
    # Ensure at least one of each type
    password = [
        random.choice(lowercase),
        random.choice(uppercase),
        random.choice(digits),
        random.choice(special)
    ]
    
    # Fill the rest with random characters
    remaining_length = length - len(password)
    all_chars = lowercase + uppercase + digits + special
    password.extend(random.choice(all_chars) for _ in range(remaining_length))
    
    # Shuffle the password
    random.shuffle(password)
    return ''.join(password)

def check_password_strength(password: str) -> Tuple[int, List[str], str]:
    """
    Analyze password strength with weighted scoring and additional checks
    """
    score = 0
    feedback = []
    
    # Reject common passwords
    if password.lower() in COMMON_PASSWORDS:
        feedback.append("❌ This is a commonly used password. Please choose something more unique.")
        return 0, feedback, "Very Weak"
    
    # Weighted scoring system
    weights = {
        'length': 2.0,      # Length is most important
        'case': 1.5,        # Case mixing is very important
        'numbers': 1.0,     # Numbers add moderate security
        'special': 1.5,     # Special characters are very important
        'complexity': 1.0   # Overall complexity bonus
    }
    
    # Check length (0-2 points with weight)
    length_score = min(len(password) / 8, 1.0) * weights['length']
    score += length_score
    if len(password) < 8:
        feedback.append("❌ Password should be at least 8 characters long")
    elif len(password) < 12:
        feedback.append("💡 Tip: Longer passwords (12+ characters) are more secure")
    
    # Check for uppercase and lowercase (0-1.5 points with weight)
    if re.search(r'[A-Z]', password) and re.search(r'[a-z]', password):
        score += weights['case']
    else:
        feedback.append("❌ Include both uppercase and lowercase letters")
    
    # Check for numbers (0-1 point with weight)
    if re.search(r'\d', password):
        score += weights['numbers']
    else:
        feedback.append("❌ Include at least one number")
    
    # Check for special characters (0-1.5 points with weight)
    if re.search(r'[!@#$%^&*]', password):
        score += weights['special']
    else:
        feedback.append("❌ Include at least one special character (!@#$%^&*)")
    
    # Additional complexity checks
    if (len(set(password)) > 10  # Good character variety
            and not re.search(r'(.)\1{2,}', password)):  # No character repetition
        score += weights['complexity']
    
    # Normalize score to 0-5 range
    max_possible_score = sum(weights.values())
    normalized_score = (score / max_possible_score) * 5
    
    # Determine strength level
    if normalized_score <= 2:
        strength = "Weak"
    elif normalized_score <= 3.5:
        strength = "Moderate"
    elif normalized_score <= 4.5:
        strength = "Strong"
    else:
        strength = "Very Strong"
    
    return round(normalized_score, 1), feedback, strength

def get_strength_color(strength: str) -> str:
    """
    Get color code for strength level
    
    Args:
        strength (str): Strength level
        
    Returns:
        str: Color code
    """
    colors = {
        "Weak": "🔴 #FF4B4B",
        "Moderate": "🟡 #FFA500",
        "Strong": "🟢 #00FF00",
        "Very Strong": "🟣 #FF00FF"
    }
    return colors.get(strength, "#FFFFFF")

def main():
    # Set page configuration
    st.set_page_config(
        page_title="Password Strength Meter",
        page_icon="🔒",
        layout="centered"
    )
    
    # Add custom CSS
    st.markdown("""
        <style>
        .main {
            padding: 2rem;
        }
        .stTextInput > div > div > input {
            font-size: 20px;
        }
        .copy-btn {
            text-align: center;
        }
        .copy-btn button {
            padding: 10px 20px;
            font-size: 16px;
            background-color: #007BFF;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }
        .copy-btn button:hover {
            background-color: #0056b3;
        }
        </style>
    """, unsafe_allow_html=True)
    
    # Main title
    st.title("🔒 Password Strength Meter")
    st.markdown("---")
    
    # Add tabs for different features
    tab1, tab2 = st.tabs(["Password Checker", "Password Generator"])
    
    with tab1:
        st.markdown("### Check Your Password Strength")
        password = st.text_input(
            "Enter your password:",
            type="password",
            help="Your password should meet the criteria listed below"
        )
        
        # Display requirements
        with st.expander("Password Requirements", expanded=True):
            st.markdown("""
            - ✅ At least 8 characters long (12+ recommended)
            - ✅ Contains uppercase & lowercase letters
            - ✅ Includes at least one digit (0-9)
            - ✅ Has one special character (!@#$%^&*)
            - ✅ Avoid common passwords and patterns
            """)
        
        if password:
            score, feedback, strength = check_password_strength(password)
            
            # Display strength meter with enhanced visuals
            st.markdown("### Password Strength:")
            strength_color = get_strength_color(strength)
            
            # Create columns for better layout
            col1, col2, col3 = st.columns([1, 2, 1])
            with col2:
                st.markdown(
                    f"<h2 style='color: {strength_color.split()[1]}; text-align: center;'>"
                    f"{strength} {strength_color.split()[0]}</h2>",
                    unsafe_allow_html=True
                )
            
            # Enhanced progress bar
            st.progress(score / 5)
            st.markdown(f"<p style='text-align: center;'><strong>Score:</strong> {score}/5</p>", 
                       unsafe_allow_html=True)
            
            # Feedback section
            if feedback:
                st.markdown("### Improvements Needed:")
                for msg in feedback:
                    st.warning(msg)
            elif strength in ["Strong", "Very Strong"]:
                st.success("🎉 Congratulations! Your password meets all security requirements!")
            
            # Password analysis
            with st.expander("Detailed Password Analysis", expanded=True):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("**Length:**")
                    st.markdown("**Uppercase:**")
                    st.markdown("**Lowercase:**")
                    st.markdown("**Numbers:**")
                    st.markdown("**Special Chars:**")
                    st.markdown("**Unique Chars:**")
                    
                with col2:
                    st.markdown(f"{'✅' if len(password) >= 8 else '❌'} ({len(password)} chars)")
                    st.markdown(f"{'✅' if re.search(r'[A-Z]', password) else '❌'}")
                    st.markdown(f"{'✅' if re.search(r'[a-z]', password) else '❌'}")
                    st.markdown(f"{'✅' if re.search('[0-9]', password) else '❌'}")
                    st.markdown(f"{'✅' if re.search(r'[!@#$%^&*]', password) else '❌'}")
                    st.markdown(f"{len(set(password))} unique characters")
    
    with tab2:
        st.markdown("### Generate a Strong Password")
        col1, col2 = st.columns([2, 1])
        
        with col1:
            length = st.slider("Password Length", min_value=8, max_value=32, value=16)
        
        with col2:
            generate_btn = st.button("Generate Password")
        
        if generate_btn:
            generated_password = generate_strong_password(length)
            st.code(generated_password)
            
            # Add copy button
            st.markdown("""
            <div class="copy-btn">
                <button onclick="navigator.clipboard.writeText('{}')">
                    Copy to Clipboard
                </button>
            </div>
            """.format(generated_password), unsafe_allow_html=True)
            
            # Show strength of generated password
            score, feedback, strength = check_password_strength(generated_password)
            st.markdown(f"**Strength:** {strength} ({score}/5)")

if __name__ == "__main__":
    main() 