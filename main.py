from flask import Flask, render_template, flash, url_for, redirect, request, jsonify
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, DateField, TimeField, IntegerRangeField, SelectField, TextAreaField,FileField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from flask_wtf.file import FileField, FileRequired, FileAllowed
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import os
import requests
import json
import base64
from datetime import datetime
import io
import tempfile
from gtts import gTTS
import google.generativeai as genai
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize Gemini
genai.configure(api_key=os.getenv('GEMINI_API_KEY'))

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', "123456789")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///interview.db'
app.config['UPLOAD_FOLDER'] = 'static/audio'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = "Please log in to access this page."

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id             = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name           = db.Column(db.String(50), nullable=False)
    email          = db.Column(db.String(120), unique=True, nullable=False)
    password_hash  = db.Column(db.String(128), nullable=False)
    pdf_data       = db.Column(db.LargeBinary, nullable=True)
    pdf_filename   = db.Column(db.String(260), nullable=True)
    jobdesc_data         = db.Column(db.LargeBinary, nullable=True)
    jobdesc_filename     = db.Column(db.String(260), nullable=True)
    conversations = db.relationship('Conversation', backref='user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Conversation(db.Model):
    __tablename__ = 'conversations'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    question_id = db.Column(db.Integer, nullable=False)
    question_title = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    messages = db.relationship('Message', backref='conversation', lazy=True)

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversations.id'), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # 'user' or 'ai'
    content = db.Column(db.Text, nullable=False)
    code_snapshot = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class SignUpForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(),Email()])
    password = PasswordField("Password", validators=[DataRequired(),Length(min=8)])
    confirm_password=PasswordField("Confirm Password", validators=[DataRequired(),EqualTo('password', message="Passwords must match.")])
    resume = FileField('Upload PDF Document',
                       validators=[
                           FileRequired(message="Please upload a PDF file."),
                           FileAllowed(['pdf'], message="Only PDF files are allowed.")])
    submit = SubmitField("Submit")

class JobDescForm(FlaskForm):
    jobdesc = FileField(
        'Upload Job Description (PDF)',
        validators=[
            FileRequired(message="Please upload a PDF file."),
            FileAllowed(['pdf'],    message="Only PDF files are allowed.")
        ]
    )
    submit = SubmitField("Proceed")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(),Email()])
    password = PasswordField("Password", validators=[DataRequired(),Length(min=8)])
    submit = SubmitField("Login")

with app.app_context():
    db.create_all()
    # Ensure audio directory exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


# Login manager user loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignUpForm()
    if form.validate_on_submit():
        # 1. Prevent duplicate emails
        if User.query.filter_by(email=form.email.data).first():
            flash("Email is already registered.", 'danger')
            return render_template('sign_up.html', form=form)

        # 2. Read and secure the uploaded PDF
        file_obj = form.resume.data            # sanitize filename
        file_bytes = file_obj.read()                   # raw bytes for BLOB

        # 3. Create the new user, including resume data
        new_user = User(
            name=form.name.data,
            email=form.email.data,
            pdf_data =file_bytes,
            pdf_filename=file_obj.filename
        )
        new_user.set_password(form.password.data)      # hash & store password

        # 4. Persist to database
        db.session.add(new_user)
        db.session.commit()

        # 5. Log in and redirect
        login_user(new_user)
        flash("Account created successfully!", 'success')
        return redirect(url_for('main'))

    return render_template('sign_up.html', form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        
        if user:
            # Check if the password is correct
            if user.check_password(form.password.data):
                login_user(user)
                return redirect(url_for('main'))
            else:
                # Wrong password
                flash("Incorrect password. Please try again.", 'danger')
        else:   
            # Account does not exist
            flash("No account found with this email. Please sign up first.", 'warning')
    
    return render_template('login.html', form=form)

@app.route('/main', methods=['GET', 'POST'])
@login_required
def main():
    form = JobDescForm()
    # If we detect a POST (modal form submission), handle it here:
    if form.validate_on_submit():
        file_obj   = form.jobdesc.data
        file_bytes = file_obj.read()
        current_user.jobdesc_data     = file_bytes
        current_user.jobdesc_filename = file_obj.filename
        db.session.commit()
        flash("Job description uploaded! Starting interview…", 'success')
        return redirect(url_for('interview'))
    return render_template('main.html', form=form)

@app.route('/interview')
@login_required
def interview():
    return render_template('interview.html')

@app.route('/start_question', methods=['POST'])
@login_required
def start_question():
    data = request.json
    question_id = data.get('question_id')
    question_title = data.get('question_title')
    
    # Create a new conversation for this question
    conversation = Conversation(
        user_id=current_user.id,
        question_id=question_id,
        question_title=question_title
    )
    db.session.add(conversation)
    db.session.commit()
    
    # Generate initial AI message
    initial_prompt = f"I'll help you solve the {question_title} problem. Let's start by understanding the problem. What's your approach?"
    
    # Add initial AI message to the conversation
    message = Message(
        conversation_id=conversation.id,
        role='ai',
        content=initial_prompt,
        code_snapshot=None
    )
    db.session.add(message)
    db.session.commit()
    
    # Generate audio for the initial prompt
    audio_url = text_to_speech(initial_prompt)
    
    return jsonify({
        'success': True,
        'conversation_id': conversation.id,
        'response': initial_prompt,
        'audio_url': audio_url
    })

def get_system_prompt(question_title, question_prompt):
    """Generate a comprehensive system prompt for the LLM"""
    return f"""You are an expert coding interviewer conducting a technical interview. The current problem is:

Title: {question_title}
Problem: {question_prompt}

Your role is to:
1. Guide the candidate through solving the problem
2. Provide hints and feedback based on their approach
3. Analyze their code and suggest improvements
4. Ask clarifying questions when needed
5. Help them understand time and space complexity
6. Provide test cases and edge cases to consider

Guidelines:
- Be encouraging but maintain professional standards
- Provide specific, actionable feedback
- Focus on problem-solving approach and code quality
- Help identify potential bugs and edge cases
- Explain concepts clearly and concisely
- Adapt your responses based on the candidate's experience level
- Keep responses focused and relevant to the current problem
- Always provide a response, even if the user's input is unclear
- If you don't understand something, ask for clarification
- If the user is stuck, provide a small hint to guide them
- If the user has written code, analyze it and provide specific feedback

Current context: You are in an active interview session. Respond naturally to the candidate's input. Never say you're having trouble processing the input - always try to provide a helpful response."""

def process_with_llm(transcript, code, question_id, conversation_history):
    """Process user input with Google's Gemini model"""
    try:
        # Get the current question details
        question_idx = question_id - 1
        if question_idx < 0 or question_idx >= 3:
            question_idx = 0
        
        questions = [
            { 
                "title": '1. 3Sum', 
                "prompt": 'Given an array nums of n integers, return all unique triplets [nums[i], nums[j], nums[k]] such that i != j, i != k, j != k, and nums[i] + nums[j] + nums[k] == 0.'
            },
            { 
                "title": '2. Add Two Numbers', 
                "prompt": 'Add two numbers represented by linked lists in reverse order.'
            },
            { 
                "title": '3. Longest Substring Without Repeating Characters', 
                "prompt": 'Find the length of the longest substring without repeating characters.'
            }
        ]
        
        question = questions[question_idx]

        # Check if API key is configured
        if not os.getenv('GEMINI_API_KEY'):
            raise ValueError("Gemini API key not found. Please set GEMINI_API_KEY in your environment variables.")
        
        # Initialize Gemini model with safety settings
        generation_config = {
            "temperature": 0.7,
            "top_p": 0.8,
            "top_k": 40,
            "max_output_tokens": 1024,
        }
        
        safety_settings = [
            {
                "category": "HARM_CATEGORY_HARASSMENT",
                "threshold": "BLOCK_MEDIUM_AND_ABOVE"
            },
            {
                "category": "HARM_CATEGORY_HATE_SPEECH",
                "threshold": "BLOCK_MEDIUM_AND_ABOVE"
            },
            {
                "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                "threshold": "BLOCK_MEDIUM_AND_ABOVE"
            },
            {
                "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                "threshold": "BLOCK_MEDIUM_AND_ABOVE"
            }
        ]
        
        model = genai.GenerativeModel(
            model_name='gemini-pro',
            generation_config=generation_config,
            safety_settings=safety_settings
        )
        
        # Prepare the conversation history
        chat = model.start_chat(history=[])
        
        # Add system prompt
        system_prompt = get_system_prompt(question["title"], question["prompt"])
        try:
            chat.send_message(system_prompt)
        except Exception as e:
            print(f"Error sending system prompt: {str(e)}")
            return "I'm having trouble initializing the conversation. Please try again."
        
        # Add conversation history
        try:
            for msg in conversation_history:
                role = "Assistant" if msg["role"] == "ai" else "User"
                chat.send_message(f"{role}: {msg['content']}")
        except Exception as e:
            print(f"Error sending conversation history: {str(e)}")
            return "I'm having trouble accessing our conversation history. Let's start fresh."
        
        # Prepare current input
        current_input = f"User's speech: {transcript}\n"
        if code and len(code.strip()) > 0:
            current_input += f"\nCurrent code:\n{code}"
        
        # Get response from Gemini with retry logic
        max_retries = 3
        retry_count = 0
        last_error = None
        
        while retry_count < max_retries:
            try:
                response = chat.send_message(current_input)
                if response and response.text:
                    return response.text
                else:
                    raise ValueError("Empty response from Gemini")
            except Exception as e:
                last_error = str(e)
                retry_count += 1
                if retry_count < max_retries:
                    print(f"Retry {retry_count} due to error: {last_error}")
                    continue
                else:
                    print(f"All retries failed. Last error: {last_error}")
                    return "I'm having trouble processing your input. Please try rephrasing your question or try again in a moment."
        
    except ValueError as ve:
        print(f"Configuration error: {str(ve)}")
        return "There's a configuration issue with the AI system. Please contact support."
    except Exception as e:
        print(f"Unexpected error in LLM processing: {str(e)}")
        return "I encountered an unexpected error. Please try again in a moment."

@app.route('/process_interview', methods=['POST'])
@login_required
def process_interview():
    data = request.json
    transcript = data.get('transcript')
    code = data.get('code')
    question_id = data.get('question_id')
    question_title = data.get('question_title')
    
    # Find the most recent conversation for this question
    conversation = Conversation.query.filter_by(
        user_id=current_user.id,
        question_id=question_id
    ).order_by(Conversation.timestamp.desc()).first()
    
    if not conversation:
        conversation = Conversation(
            user_id=current_user.id,
            question_id=question_id,
            question_title=question_title
        )
        db.session.add(conversation)
        db.session.commit()
    
    # Add user message to the conversation
    user_message = Message(
        conversation_id=conversation.id,
        role='user',
        content=transcript,
        code_snapshot=code
    )
    db.session.add(user_message)
    db.session.commit()
    
    # Get conversation history
    messages = Message.query.filter_by(conversation_id=conversation.id).order_by(Message.timestamp).all()
    conversation_history = [{"role": msg.role, "content": msg.content} for msg in messages]
    
    # Process with LLM
    ai_response = process_with_llm(transcript, code, question_id, conversation_history)
    
    # Add AI response to the conversation
    ai_message = Message(
        conversation_id=conversation.id,
        role='ai',
        content=ai_response,
        code_snapshot=code
    )
    db.session.add(ai_message)
    db.session.commit()
    
    # Generate audio for the AI response
    audio_url = text_to_speech(ai_response)
    
    return jsonify({
        'success': True,
        'response': ai_response,
        'audio_url': audio_url
    })

def text_to_speech(text):
    """Convert text to speech and save as audio file"""
    # Create a unique filename
    filename = f"response_{datetime.now().strftime('%Y%m%d%H%M%S%f')}.mp3"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    # Generate speech using gTTS
    tts = gTTS(text=text, lang='en', slow=False)
    tts.save(filepath)
    
    # Return the URL to the audio file
    return url_for('static', filename=f'audio/{filename}')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
