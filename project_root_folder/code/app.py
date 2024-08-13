import math
from flask import Flask, abort,render_template,redirect, flash,request, url_for, session,get_flashed_messages,flash 
from dotenv import load_dotenv 
from sqlalchemy import func , and_, or_, not_, select
from flask_login import LoginManager, login_user, login_required, current_user, logout_user 
from werkzeug.security import generate_password_hash, check_password_hash 
import logging
from sqlalchemy.exc import IntegrityError 
from werkzeug.utils import secure_filename

from functools import wraps
import os

from models_ import db, User, AdRequest, Campaign, Role, Status, Visibility

from functions import process_date, processing_date

load_dotenv()

app = Flask(__name__)


app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.environ.get('SQLALCHEMY_TRACK_MODIFICATIONS')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')

UPLOAD_FOLDER = 'static/images/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit

db.init_app(app)

# CREATE LOGIN MANAGER
login_manager = LoginManager()
login_manager.init_app(app)

# CREATE USER LOADER CALLBACK
@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, int(user_id))

with app.app_context():
    db.create_all()
    admin = User.query.filter_by(role=Role.ADMIN).first()
    if not admin:
      password = 'admin1234'
      password_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
      admin = User(
        name='Admin Pookie',
        email='admin@email.com',
        password_hash=password_hash,
        role=Role.ADMIN
      )
      
      db.session.add(admin)
      db.session.commit()


@app.context_processor
def inject_global():
  context = {
    'current_user': current_user,
  }
  
  return context

def admin_required(func):
  @wraps(func)
  def decorated_view(*args, **kwargs):
    if not current_user.is_authenticated or current_user.role != Role.ADMIN:
      flash("Access denied. Admin role required.", "danger")
      return redirect(url_for('login_page'))
    return func(*args, **kwargs)
  return decorated_view

def sponsor_required(func):
  @wraps(func)
  def decorated_view(*args, **kwargs):
    if not current_user.is_authenticated or current_user.role != Role.SPONSOR:
      flash("Access denied. Sponsor role required.", "danger")
      return redirect(url_for('login_page'))
    return func(*args, **kwargs)
  return decorated_view

def influencer_required(func):
  @wraps(func)
  def decorated_view(*args, **kwargs):
    if not current_user.is_authenticated or current_user.role != Role.INFLUENCER:
      flash("Access denied. Influencer role required.", "danger")
      return redirect(url_for('login_page'))
    return func(*args, **kwargs)
  return decorated_view

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

#==============================================BASE ROUTES==============================================
@app.route('/')
def login_page():
  return render_template('base_login.html')

@app.route('/signup')
def signup_page():
  return render_template('base_signup.html')

#==============================================ADMIN ROUTES==============================================

#Admin Login Page
@app.route('/Admin/login', methods=["GET", "POST"])
def admin_login():
  if request.method == "POST":
    email = request.form.get('email')
    password = request.form.get('password')

    # Check if admin exists
    user = db.session.execute(db.select(User).where(User.email == email)).scalar()

    if not user or not check_password_hash(user.password_hash, password):
      flash("Incorrect email or password", "danger")
      return redirect(url_for('admin_login'))
    elif user.role == Role.SPONSOR:
      flash("Access denied. Admin role required.", "danger")
      return redirect(url_for('admin_login'))
    elif user.role == Role.INFLUENCER:
      flash("Access denied. Admin role required.", "danger")
      return redirect(url_for('admin_login'))
    else:
      login_user(user)
      return redirect(url_for('admin_dashboard'))  
    
  return render_template('Admin/a_login.html')

#Admin Logout
@app.route('/Admin/logout')
@admin_required
def admin_logout():
  logout_user()
  return redirect(url_for('admin_login'))

#Admin Dashboard
@app.route('/Admin/dashboard')
@admin_required
def admin_dashboard():
  # Fetch the number of sponsors
  num_sponsors = db.session.execute(db.select(func.count(User.user_id)).where(User.role == Role.SPONSOR)).scalar()
  
  # Fetch the number of influencers
  num_influencers = db.session.execute(db.select(func.count(User.user_id)).where(User.role == Role.INFLUENCER)).scalar()
  
  # Fetch the number of campaigns
  num_campaigns = db.session.execute(db.select(func.count(Campaign.campaign_id))).scalar()
  
  total_entities = num_sponsors + num_influencers
  
  # Fetch the number of sponsors which are flagged
  num_flagged_sponsors = db.session.execute(db.select(func.count(User.user_id)).where(and_(User.role == Role.SPONSOR, User.flagged == True))).scalar()
  
  # Fetch the number of influencers which are flagged
  num_flagged_influencers = db.session.execute(db.select(func.count(User.user_id)).where(and_(User.role == Role.INFLUENCER, User.flagged == True))).scalar()
  
  # Fetch the number of campaigns which are flagged
  num_flagged_campaigns = db.session.execute(db.select(func.count(Campaign.campaign_id)).where(Campaign.flagged == True)).scalar()
  
  total_flagged_entities = num_flagged_sponsors + num_flagged_influencers + num_flagged_campaigns
  
  # Fetch top 5 most recent campaigns
  recent_campaigns = db.session.execute(db.select(Campaign).order_by(Campaign.start_date.desc()).limit(5)).scalars().all()
  
  
  return render_template('Admin/a_dashboard.html', num_sponsors=num_sponsors, num_influencers=num_influencers, num_campaigns=num_campaigns, num_flagged_sponsors=num_flagged_sponsors, num_flagged_influencers=num_flagged_influencers, num_flagged_campaigns=num_flagged_campaigns, total_flagged_entities=total_flagged_entities, total_entities=total_entities, recent_campaigns=recent_campaigns)

#Admin Sponsors
@app.route('/Admin/Sponsors-pg')
@admin_required
def admin_sponsors():
  sponsors = db.session.execute(db.select(User).where(User.role == Role.SPONSOR)).scalars().all()
  return render_template('Admin/a_sponsors.html', sponsors=sponsors)

#Sponsor Toggle
@app.route('/Admin/Sponsors-pg/ToggleFlag/<int:sponsor_id>')
@admin_required
def toggle_sponsor_flag(sponsor_id):
  sponsor = db.session.execute(db.select(User).where(User.user_id == sponsor_id, User.role == Role.SPONSOR)).scalar()
  if sponsor:
    sponsor.flagged = not sponsor.flagged
    db.session.commit()
    if sponsor.flagged:
      flash('Sponsor flagged successfully', 'success')
    else:
      flash('Sponsor unflagged successfully', 'success')
  return redirect(url_for('admin_sponsors'))

#Sponsor Deletion
@app.route('/Admin/Sponsors-pg/Delete/<int:sponsor_id>')
@admin_required
def delete_sponsor(sponsor_id):
  sponsor = db.session.execute(db.select(User).where(User.user_id == sponsor_id, User.role == Role.SPONSOR)).scalar()
  if sponsor:
    db.session.delete(sponsor)
    db.session.commit()
    flash('Sponsor deleted successfully', 'success')
  return redirect(url_for('admin_sponsors'))

#Admin Influencers
@app.route('/Admin/Influencers-pg')
@admin_required
def admin_influencers():
  influencers = db.session.execute(db.select(User).where(User.role == Role.INFLUENCER)).scalars().all()
  return render_template('Admin/a_inf.html', influencers=influencers)

#Influencer Toggle
@app.route('/Admin/Influencers-pg/ToggleFlag/<int:influencer_id>')
@admin_required
def toggle_influencer_flag(influencer_id):
  influencer = db.session.execute(db.select(User).where(User.user_id == influencer_id, User.role == Role.INFLUENCER)).scalar()
  if influencer:
    influencer.flagged = not influencer.flagged
    db.session.commit()
    if influencer.flagged:
      flash('Influencer flagged successfully', 'success')
    else:
      flash('Influencer unflagged successfully', 'success')
  return redirect(url_for('admin_influencers'))

#Influencer Deletion
@app.route('/Admin/Influencers-pg/Delete/<int:influencer_id>')
@admin_required
def delete_influencer(influencer_id):
  influencer = db.session.execute(db.select(User).where(User.user_id == influencer_id, User.role == Role.INFLUENCER)).scalar()
  if influencer:
    db.session.delete(influencer)
    db.session.commit()
    flash('Influencer deleted successfully', 'success')
  return redirect(url_for('admin_influencers'))

#Admin Campaigns
@app.route('/Admin/Campaigns-pg')
@admin_required
def admin_campaigns():
  campaigns = db.session.execute(db.select(Campaign)).scalars().all()
  return render_template('Admin/a_campaigns.html', campaigns=campaigns)

#Campaign Toggle
@app.route('/Admin/Campaigns/ToggleFlag/<int:campaign_id>')
@admin_required
def toggle_campaign_flag(campaign_id):
  campaign = db.session.execute(db.select(Campaign).where(Campaign.campaign_id == campaign_id)).scalar()
  if campaign:
    campaign.flagged = not campaign.flagged
    db.session.commit()
    if campaign.flagged:
      flash('Campaign flagged successfully', 'success')
    else:
      flash('Campaign unflagged successfully', 'success')
  return redirect(url_for('admin_campaigns'))

#Campaign Deletion
@app.route('/Admin/Campaigns-pg/Delete/<int:campaign_id>')
@admin_required
def a_delete_campaign(campaign_id):
  campaign = db.session.execute(db.select(Campaign).where(Campaign.campaign_id == campaign_id)).scalar()
  if campaign:
    db.session.delete(campaign)
    db.session.commit()
    flash('Campaign deleted successfully', 'success')
  return redirect(url_for('admin_campaigns'))

#Admin Requests
@app.route('/Admin/Requests-pg')
@admin_required
def admin_requests():
  requests = db.session.execute(db.select(AdRequest)).scalars().all()
  return render_template('Admin/a_requests.html', requests=requests)

#Request Deletion
@app.route('/Admin/Requests-pg/Delete/<int:request_id>')
@admin_required
def delete_request(request_id):
  request = db.session.execute(db.select(AdRequest).where(AdRequest.request_id == request_id)).scalar()
  if request:
    db.session.delete(request)
    db.session.commit()
    flash('Request deleted successfully', 'success')
  return redirect(url_for('admin_requests'))

#==============================================SPONSOR ROUTES==============================================

#Sponsor Login Page
@app.route('/Sponsors/login', methods=["GET", "POST"])
def sponsor_login():
  if request.method == "POST":
    email = request.form.get('email')
    password = request.form.get('password')

    # Check if sponsor exists
    user = db.session.execute(db.select(User).where(User.email == email)).scalar()

    if not user or not check_password_hash(user.password_hash, password):
      flash("Incorrect email or password/Your account has been deleted.", "danger")
      return redirect(url_for('sponsor_login'))
    elif user.role == Role.ADMIN:
      flash("Access denied. Sponsor role required.", "danger")
      return redirect(url_for('sponsor_login'))
    elif user.role == Role.INFLUENCER:
      flash("Access denied. Sponsor role required.", "danger")
      return redirect(url_for('sponsor_login'))
    
    #If user is an influencer
    if user.role == Role.SPONSOR:
      if user.flagged:
        flash("Access denied. Your account has been flagged.", "danger")
        return redirect(url_for('sponsor_login'))
      login_user(user)
      return redirect("/Sponsors/dashboard")
        
    flash("Access denied. Invalid role.", "danger")
    return redirect(url_for('influencer_login'))
  return render_template('Sponsors/s_login.html')

#Sponsor Signup Page
@app.route('/Sponsors/signup', methods=["GET", "POST"])
def sponsor_signup():
  if request.method == "POST":
    name = request.form.get('name')
    email = request.form.get('email')
    password = request.form.get('password')

    # Check if user already exists
    sponsor = db.session.execute(db.select(User).where(User.email == email, User.role == Role.SPONSOR)).scalar()
    if sponsor:
      flash("Email already exists. Please login.", "danger")
      return redirect(url_for('sponsor_signup'))
    
    # Create a password hash
    hash_and_salted_password = generate_password_hash(
      password,
      method='pbkdf2:sha256',
      salt_length=8
    )

    # Create new sponsor
    new_sponsor = User(
      name=name,
      email=email,
      password_hash=hash_and_salted_password,
      role = Role.SPONSOR
    )

    db.session.add(new_sponsor)
    db.session.commit()

    # Log in the new sponsor
    login_user(new_sponsor)
    return redirect(url_for('sponsor_dashboard'))
  return render_template('Sponsors/s_signup.html')

#Sponsor Logout
@app.route('/Sponsors/logout')
@sponsor_required
def sponsor_logout():
  logout_user()
  return redirect(url_for('sponsor_login'))

#Sponsor Dashboard
@app.route('/Sponsors/dashboard')
@sponsor_required
def sponsor_dashboard():
  # Get all campaigns for the sponsor
  campaigns = db.session.execute(db.select(Campaign).where(Campaign.user_id == current_user.user_id)).scalars().all()
  return render_template('Sponsors/s_dashboard.html', campaigns=campaigns)

#Sponsor Add Campaign
@app.route('/Sponsors/add-campaign', methods=["GET", "POST"])
@sponsor_required
def add_campaign():
    if request.method == "POST":
        title = request.form.get('campaign_title')
        description = request.form.get('description')
        budget = float(request.form.get('budget'))
        start_date = request.form.get('start_date')  # %Y-%m-%d
        end_date = request.form.get('end_date')       # %Y-%m-%d
        visibility = request.form.get('visibility')
        
        # Check for visibility and process niches if visibility is private
        if visibility == 'private':
            niche = request.form.get('niche')  # Get the selected niches
            if niche == '':
               niche = 'All'
        else:
            niche = 'All'

        if start_date > end_date:
            flash("Campaign cannot end before it starts", "danger")
            return redirect(url_for('add_campaign'))
        
        new_campaign = Campaign(
            title=title,
            description=description,
            budget=budget,
            start_date=process_date(start_date), 
            end_date=process_date(end_date),
            visibility=Visibility.PUBLIC if visibility == 'public' else Visibility.PRIVATE,
            user_id=current_user.user_id,
            status=Status.ACTIVE,
            niche=niche 
        )
        
        db.session.add(new_campaign)
        db.session.commit()
        

        return redirect(url_for('sponsor_dashboard'))
    
    return render_template('Sponsors/s_add_campaign.html')


#Sponsor Edit Campaign Form
@app.route('/Sponsors/edit-campaign/<int:campaign_id>', methods=["GET", "POST"])
@sponsor_required
def edit_campaign(campaign_id):
  campaign = db.session.execute(db.select(Campaign).where(Campaign.campaign_id == campaign_id)).scalar()
  return render_template('Sponsors/s_edit_campaign.html', campaign=campaign)

#Sponsor Edit Campaign
@app.route('/Sponsors/update-campaign/<int:campaign_id>', methods=["GET", "POST"])
@sponsor_required
def update_campaign(campaign_id,):
  if request.method == "POST":
  # Retrieve form data
    title = request.form.get('campaign_title')
    description = request.form.get('description')
    budget = request.form.get('budget')  # No need to convert to float immediately
    start_date = request.form.get('start_date')
    end_date = request.form.get('end_date')
    visibility = request.form.get('visibility')
    status = request.form.get('status')
      
      # Check if visibility is 'private' and process niche
    niche = request.form.get('niche') if visibility == 'private' else 'All'

  # Ensure all required fields are provided
  if not (title and description and budget and start_date and end_date and visibility and status):
        print('Not all required fields are provided')
        flash("All fields are required", "danger")
        return redirect(url_for('edit_campaign', campaign_id=campaign_id))

    # Update campaign fields
  else:
        campaign = db.session.execute(db.select(Campaign).where(Campaign.campaign_id == campaign_id)).scalar()
        campaign.title = title
        campaign.description = description
        campaign.budget = float(budget)  # Convert budget to float
        campaign.start_date = process_date(start_date)
        campaign.end_date = process_date(end_date)
        campaign.visibility = Visibility.PUBLIC if visibility == 'public' else Visibility.PRIVATE
        campaign.status = Status.ACTIVE if status == 'active' else Status.INACTIVE
        campaign.niche = niche

        # Commit changes to the database
        db.session.commit()
        flash("Campaign updated successfully", "success")

  return redirect(url_for('edit_campaign', campaign_id=campaign_id))


#Delete Campaign
@app.route('/Sponsors/delete-campaign/<int:campaign_id>')
@sponsor_required
def delete_campaign(campaign_id):
  campaign = db.session.execute(db.select(Campaign).where(Campaign.campaign_id == campaign_id)).scalar()

  db.session.delete(campaign)
  db.session.commit()
  return redirect(url_for('sponsor_dashboard'))

#Sponsor Profile
@app.route('/Sponsors/Profile-pg')
@sponsor_required
def sponsor_profile():
  user = db.session.execute(db.select(User).where(User.user_id == current_user.user_id)).scalar()
  date = processing_date(str(user.signup_date))
  return render_template('Sponsors/s_profile.html', user=user, date=date)

#Sponsor Edit Profile
@app.route('/Sponsors/Edit-Profile', methods=["GET", "POST"])
@sponsor_required
def sponsor_edit_profile():
    if request.method == "POST":
        email = request.form.get('email')
        image = request.files.get('image')

        user = db.session.execute(db.select(User).where(User.user_id == current_user.user_id)).scalar()
        

        if email:
          user.email = email

        remove_image = request.form.get('remove_image') #for the remove image button
        if remove_image:
            user.image = 'profile.png'
        elif image and allowed_file(image.filename):
          filename = secure_filename(image.filename)
          unique_filename = f"{user.user_id}_{filename}"
          image_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
          image.save(image_path)
          user.image = unique_filename
           
        db.session.commit()

        flash('Profile updated successfully', 'success')
        return redirect(url_for('sponsor_profile'))
        

#Sponsor View Campaign
@app.route('/Sponsors/view-campaign/<int:campaign_id>')
@sponsor_required
def sponsor_view_campaign(campaign_id):
  campaign = db.session.execute(db.select(Campaign).where(Campaign.campaign_id == campaign_id)).scalar()
  count =db.session.execute(db.select(func.count()).select_from(AdRequest).where(AdRequest.campaign_id == campaign_id)).scalar()
  return render_template('Sponsors/s_view_campaign.html', campaign=campaign, count=count)

#Sponsor Campaign status change(Active/Inactive)
@app.route('/Sponsors/Campaign-Status/<int:campaign_id>')
@sponsor_required
def s_campaign_status(campaign_id):
  campaign = db.session.execute(db.select(Campaign).where(Campaign.campaign_id == campaign_id)).scalar()
  if campaign.status == Status.ACTIVE:
    campaign.status = Status.INACTIVE
  else:
    campaign.status = Status.ACTIVE

  db.session.commit()
  flash('Campaign status updated successfully', 'success')
  return redirect(url_for('sponsor_dashboard'))

#My Requests(Sponsor)
@app.route('/Sponsors/My-Requests-pg')
@sponsor_required
def s_my_requests():
    # Fetch all requests where sender is the current user
    requests = db.session.execute(db.select(AdRequest).where(AdRequest.sender_id == current_user.user_id)).scalars().all()
    return render_template('Sponsors/s_my_req.html', requests=requests)
  
@app.route('/Sponsors/My-Requests/Complete/<int:request_id>')
@sponsor_required
def s_my_requests_complete(request_id):
  request = db.session.execute(db.select(AdRequest).where(AdRequest.request_id == request_id)).scalar()
  campaign = db.session.execute(db.select(Campaign).where(Campaign.campaign_id == request.campaign_id)).scalar()
  if request:
    request.status = Status.COMPLETED
    campaign.budget -= request.amount
    db.session.commit()
    flash('Request marked as complete', 'success')
  return redirect(url_for('s_my_requests'))
  
#Edit My Requests(Sponsor)
@app.route('/Sponsors/Edit-Request/<int:request_id>', methods=['GET', 'POST'])
@sponsor_required
def s_edit_request(request_id):
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        budget = float(request.form.get('budget'))
        deadline = request.form.get('deadline')

        adrequest = db.session.execute(db.select(AdRequest).where(AdRequest.request_id == request_id)).scalar_one_or_none()

        if not(title or description or budget or deadline):
          flash('All fields are required!', 'danger')
          return redirect(url_for('s_edit_request', request_id=request_id))
        
        elif (process_date(deadline) > adrequest.campaign.end_date.date()) or (process_date(deadline) < adrequest.campaign.start_date.date()):
          flash('Deadline should be within the campaign date!', 'danger')
          return redirect(url_for('s_edit_request', request_id=request_id))
        
        else:
          adrequest.title = title
          adrequest.description = description
          adrequest.amount = budget
          adrequest.deadline = process_date(deadline)
          db.session.commit()
          flash('Request updated successfully!', 'success')
          return redirect(url_for('s_my_requests'))

    adrequest = db.session.execute(db.select(AdRequest).where(AdRequest.request_id == request_id)).scalar_one_or_none()
    return render_template('Sponsors/s_edit_req.html', adrequest=adrequest)



#Delete My Requests
@app.route('/Sponsors/delete-my-request/<int:request_id>')
@sponsor_required
def s_delete_request(request_id):
    request = db.session.get(AdRequest, request_id)
    if not request:
        flash('Request not found!', 'error')
        return redirect(url_for('s_my_requests'))
    db.session.delete(request)
    db.session.commit()
    flash('Request deleted successfully!', 'success')
    return redirect(url_for('s_my_requests'))

#Sponsor Requests sent by Influencers(RETRIEVAL PAGE)
@app.route('/Sponsors/Influencer-Requests')
@sponsor_required
def s_inf_requests():
    pending_requests = db.session.query(AdRequest).join(Campaign).filter(AdRequest.status == 'PENDING', Campaign.user_id == current_user.user_id, AdRequest.sender_id != current_user.user_id).all()
    accepted_requests = db.session.query(AdRequest).join(Campaign).filter(AdRequest.status == 'ACCEPTED', Campaign.user_id == current_user.user_id, AdRequest.sender_id != current_user.user_id).all()
    rejected_requests = db.session.query(AdRequest).join(Campaign).filter(AdRequest.status == 'REJECTED', Campaign.user_id == current_user.user_id, AdRequest.sender_id != current_user.user_id).all()
    completed_requests = db.session.query(AdRequest).join(Campaign).filter(AdRequest.status == 'COMPLETED', Campaign.user_id == current_user.user_id, AdRequest.sender_id != current_user.user_id).all()
    return render_template('Sponsors/s_inf_request.html', pending_requests=pending_requests, accepted_requests=accepted_requests, rejected_requests=rejected_requests, completed_requests=completed_requests)


#Sponsors Update Request Status
@app.route('/Sponsors/update_request_status/<int:request_id>/<string:status>', methods=['GET'])
@sponsor_required
def update_request_status(request_id, status):
    request = db.session.execute(db.select(AdRequest).where(AdRequest.request_id == request_id)).scalar_one_or_none()
    if request:
        request.status = status
        db.session.commit()
    return redirect(url_for('s_inf_requests'))


#Sponsor Requests sent to Influencers(RETRIEVAL PAGE)
@app.route('/Sponsors/Request-Form/<int:campaign_id>/<string:name>', methods=['GET'])
@sponsor_required
def sponsor_request_form(campaign_id,name):
    name = name
    campaign = db.session.get(Campaign, campaign_id)
    if not campaign or campaign.user_id != current_user.user_id:
        abort(404)
    return render_template('Sponsors/s_req.html',campaign=campaign, name=name)


#Sponsor Requests sent to Influencers(FORM)
@app.route('/Sponsors/Request-Form-Post/<int:campaign_id>/<string:name>', methods=['POST'])
@sponsor_required
def sponsor_request_post(campaign_id,name):
  if request.method == 'POST':
    title = request.form.get('title')
    description = request.form.get('description')
    budget = float(request.form.get('budget'))
    user_id = current_user.user_id
    deadline = request.form.get('deadline')

    campaign = db.session.get(Campaign, campaign_id)
    if campaign.budget < budget:
      flash('Budget exceeds the campaign budget!', 'danger')
      return redirect(url_for('sponsor_request_form', campaign_id=campaign_id, name=name))

    elif (process_date(deadline) > campaign.end_date.date()) or (process_date(deadline) < campaign.start_date.date()):
      flash('Deadline should be within the campaign date!', 'danger')
      return redirect(url_for('sponsor_request_form', campaign_id=campaign_id, name=name))
    
    else:
      new_request = AdRequest(
      title=title,
      description=description,
      amount=budget,
      status=Status.PENDING,
      deadline=process_date(deadline),
      sender_id=user_id,
      campaign_id=campaign_id
    )

    db.session.add(new_request)
    db.session.commit()
    flash('Request sent successfully!', 'success')
    return redirect(url_for('sponsor_dashboard'))
    
  return redirect(url_for('sponsor_request', campaign_id=campaign_id, name=name))
      
#Search Influencers
@app.route('/Sponsors/search_influencers', methods=['GET'])
@sponsor_required
def search_influencers():
    query = request.args.get('query')
    print(f"Received search query: {query}")  # Debug print
    if query:
        results = User.query.filter(
           (User.flagged == False) &
            (User.role == Role.INFLUENCER) &
            (User.flagged == False) &
            ((User.name.ilike(f'%{query}%')) | 
             (User.niche.ilike(f'%{query}%')) |
             (User.platform.ilike(f'%{query}%')))
        ).all()
        print(f"Found {len(results)} results")  # Debug print
        return render_template('search_inf.html', results=results, query=query)
    else:
        print("No query provided, redirecting to dashboard")  # Debug print
        return redirect(url_for('sponsor_dashboard'))

# Sponsor Negotiation Pg
@app.route('/Sponsors/negotiation-page', methods=['GET'])
@sponsor_required
def s_negotiation_page():
    #fetch all the requests under this sponsor campaigns where this user is the receiver and the status is influencer_counter
    requests = db.session.query(AdRequest).join(Campaign).filter(AdRequest.status == Status.INFLUENCER_COUNTER,Campaign.user_id == current_user.user_id, AdRequest.receiver_id == current_user.user_id).all()
    print(requests)
    return render_template('Sponsors/s_negotiation.html', requests=requests)

#Sponsor Negotiation Form
@app.route('/Sponsors/Negotiation-Form/<int:request_id>', methods=['GET', 'POST'])
@sponsor_required
def s_negotiation_form(request_id):
    data = db.session.execute(db.select(AdRequest).where(AdRequest.request_id == request_id)).scalar_one_or_none()
    if not data:
        flash('Request not found!', 'error')
        return redirect(url_for('s_inf_requests'))
    return render_template('Sponsors/sponsor_negotiation_form.html', data=data)

#Sponsor Negotiation Form Submit
@app.route('/Sponsors/Negotiation-Form-Post/<int:request_id>', methods=['POST'])
@sponsor_required
def s_negotiation_form_post(request_id):
    if request.method == 'POST':
      counter_amount = float(request.form.get('counter_amount'))
      data = db.session.execute(db.select(AdRequest).where(AdRequest.request_id == request_id)).scalar_one_or_none()
      if not data:
          flash('Request not found!', 'error')
          print('request not found')
          return redirect(url_for('s_inf_requests'))
      data.status = Status.SPONSOR_COUNTER
      data.amount = counter_amount
      data.receiver_id = data.sender_id
      data.sender_id = current_user.user_id
      db.session.commit()
      flash('Negotiation form submitted successfully!', 'success')
      print('negotiation offer sent')
      return redirect(url_for('s_inf_requests'))
    
       
#==============================================INFLUENCER ROUTES==============================================

#Influencer Login    
@app.route('/Influencers/login', methods=["GET", "POST"])
def influencer_login():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')
        
        print(f"Login attempt for email: {email}")
        
        # Check if influencer exists
        user = db.session.execute(db.select(User).where(User.email == email)).scalar()
        
        if not user:
            flash("Invalid email or password/Your account has been deleted.", "danger")
            print("Flash: Invalid email or password")
            return redirect(url_for('influencer_login'))
        
        print(f"User found. Role: {user.role}")
        
        if not check_password_hash(user.password_hash, password):
            flash("Invalid email or password", "danger")
            print("Flash: Invalid email or password")
            return redirect(url_for('influencer_login'))
        
        if user.role == Role.ADMIN:
            flash("Access denied. Admin role required.", "danger")
            print("Flash: Access denied. Admin role required.")
            return redirect(url_for('influencer_login'))
        
        if user.role == Role.SPONSOR:
            flash("Access denied. Sponsor role required.", "danger")
            print("Flash: Access denied. Sponsor role required.")
            return redirect(url_for('influencer_login'))
        
        # If user is an influencer
        if user.role == Role.INFLUENCER:
            if user.flagged:
                flash("Access denied. Your account has been flagged.", "danger")
                return redirect(url_for('influencer_login'))
            login_user(user)
            return redirect("/Influencers/dashboard")
        
        flash("Access denied. Invalid role.", "danger")
        return redirect(url_for('influencer_login'))

    return render_template('Influencers/i_login.html')



#Influencer Signup
@app.route('/Influencers/signup', methods=["GET", "POST"])
def influencer_signup():
    if request.method == "POST":
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        niche = request.form.get('niche')
        platform = request.form.get('platform')
        reach = request.form.get('reach')

        # Check if user already exists
        influencer = db.session.execute(db.select(User).where(User.email == email, User.role == Role.INFLUENCER)).scalar()
        if influencer:
            flash("Email already exists. Please login.", "danger")
            return redirect(url_for('influencer_login'))
        
        # Create a password hash
        hash_and_salted_password = generate_password_hash(
            password,
            method='pbkdf2:sha256',
            salt_length=8
        )

        # Create new influencer
        new_influencer = User(
            name=name,
            email=email,
            password_hash=hash_and_salted_password,
            role=Role.INFLUENCER,
            niche=niche,
            platform=platform,
            reach=reach
        )

        db.session.add(new_influencer)
        db.session.commit()

        # Log in the new influencer
        login_user(new_influencer)
        return redirect(url_for('influencer_dashboard'))
    
    return render_template('Influencers/i_signup.html')



#Influencer Logout
@app.route('/Influencers/logout')
@influencer_required
def influencer_logout():
  logout_user()
  return redirect(url_for('influencer_login'))


#Influencer Dashboard
@app.route('/Influencers/dashboard')
@influencer_required
def influencer_dashboard():
  # Get the current user's details
    influencer = User.query.get(current_user.user_id)
    
    if influencer:
        score = round(math.log(influencer.reach + 1) if influencer.reach else 0)
        date = processing_date(str(influencer.signup_date))
        return render_template('Influencers/i_dashboard.html', influencer=influencer, score=score, date=date)
    else:
        # Handle the case where the user is not found
        return "User not found", 404


#Influencer Profile form
@app.route('/Influencers/Profile-pg')
@influencer_required
def influencer_profile():
  user = db.session.execute(db.select(User).where(User.user_id == current_user.user_id)).scalar()
  date = processing_date(str(user.signup_date))
  return render_template('Influencers/i_profile.html', user=user, date=date)


#Influencer Edit Profile
@app.route('/Influencers/Edit-Profile', methods=["GET", "POST"])
@influencer_required
def i_edit_profile():
  if request.method == "POST":
    email = request.form.get('email')
    niche = request.form.get('niche')
    platform = request.form.get('platform')
    reach = request.form.get('reach')
    image= request.files.get('image')

    user = db.session.execute(db.select(User).where(User.user_id == current_user.user_id)).scalar()
    user.email = email
    user.niche = niche
    user.platform = platform
    user.reach = reach

    remove_image = request.form.get('remove_image') #for the remove image button
    if remove_image:
      user.image = 'profile.png'
      # for the image file
    elif image and allowed_file(image.filename):
      filename = secure_filename(image.filename)
      unique_filename = f"{user.user_id}_{filename}"
      image_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
      image.save(image_path)
      user.image = unique_filename    
           
    db.session.commit()

    flash('Profile updated successfully', 'success')
    return redirect(url_for('influencer_profile'))
  
     

#Influencer Request Form
@app.route('/Influencers/Request-Form/<int:campaign_id>')
@influencer_required
def inf_request_form(campaign_id):
  campaign = db.session.execute(db.select(Campaign).where(Campaign.campaign_id == campaign_id)).scalar()
  print(current_user.user_id)
  return render_template('Influencers/i_request_form.html', campaign=campaign)

#Influencer request sent to sponsor
@app.route('/Influencers/Request-Form-Post/<int:campaign_id>', methods=['GET', 'POST'])
@influencer_required
def inf_sent_request(campaign_id):
    campaign = db.session.execute(db.select(Campaign).where(Campaign.campaign_id == campaign_id, Campaign.status == Status.ACTIVE)).scalar_one_or_none()
    
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        budget = float(request.form.get('budget'))    
        user_id = current_user.user_id
        deadline = request.form.get('deadline')

        campaign = db.session.get(Campaign, campaign_id)
        if campaign.budget < budget:
          flash('Budget exceeds the campaign budget!', 'danger')
          return redirect(url_for('inf_request_form', campaign_id=campaign_id))

        elif (process_date(deadline) > campaign.end_date.date()) or (process_date(deadline) < campaign.start_date.date()):
          flash('Deadline should be within the campaign date!', 'danger')
          return redirect(url_for('inf_request_form', campaign_id=campaign_id))
    
        else:
          new_request = AdRequest(
          title=title,
          description=description,
          amount=budget,
          status=Status.PENDING,
          deadline=process_date(deadline),
          sender_id=user_id,
          campaign_id=campaign_id
        )

        db.session.add(new_request)
        db.session.commit()
        flash('Request sent successfully!', 'success')
        return redirect(url_for('influencer_dashboard'))
    return render_template('Influencers/i_request_form.html', campaign=campaign)


#Edit My Requests(Influencer)
@app.route('/Influencers/Edit-Request/<int:request_id>', methods=['GET', 'POST'])
@influencer_required
def i_edit_request(request_id):
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        budget = float(request.form.get('budget'))
        deadline = request.form.get('deadline')

        adrequest = db.session.execute(db.select(AdRequest).where(AdRequest.request_id == request_id)).scalar_one_or_none()

        if not(title or description or budget or deadline):
          flash('All fields are required!', 'danger')
          return redirect(url_for('i_edit_request', request_id=request_id))
        
        elif (process_date(deadline) > adrequest.campaign.end_date.date()) or (process_date(deadline) < adrequest.campaign.start_date.date()):
          flash('Deadline should be within the campaign date!', 'danger')
          return redirect(url_for('i_edit_request', request_id=request_id))
        
        else:
          adrequest.title = title
          adrequest.description = description
          adrequest.amount = budget
          adrequest.deadline = process_date(deadline)
          db.session.commit()
          flash('Request updated successfully!', 'success')
          return redirect(url_for('i_my_requests'))

    adrequest = db.session.execute(db.select(AdRequest).where(AdRequest.request_id == request_id)).scalar_one_or_none()
    return render_template('Influencers/i_edit_req.html', adrequest=adrequest)


#Influencer Requests sent by sponsors
@app.route('/Influencers/Sponsor-Request-Page')
@influencer_required
def i_sponsor_request():

# First, create the subquery for rejected requests
  rejected_requests_subquery = select(AdRequest.request_id)\
    .join(AdRequest.rejected_by)\
    .filter(User.user_id == current_user.user_id)\
    .scalar_subquery()

# Now use this subquery in your main query
  pending_requests = db.session.query(AdRequest)\
    .join(User, AdRequest.sender_id == User.user_id)\
    .join(Campaign, AdRequest.campaign_id == Campaign.campaign_id)\
    .filter(
        User.role == Role.SPONSOR,
        AdRequest.status == Status.PENDING,
        AdRequest.receiver_id == None,
        ~AdRequest.request_id.in_(rejected_requests_subquery)
    ).all()
   
   # Fetch all accepted requests where receiver is current user and status is accepted
  accepted_requests = db.session.query(AdRequest).join(User, AdRequest.sender_id == User.user_id).join(Campaign, AdRequest.campaign_id == Campaign.campaign_id).filter(
        User.role == Role.SPONSOR,
        AdRequest.status == Status.ACCEPTED,
        AdRequest.receiver_id == current_user.user_id
    ).all()
   
   # Fetch all completed requests where receiver is current user and status is complete
  completed_requests = db.session.query(AdRequest).join(User, AdRequest.sender_id == User.user_id).join(Campaign, AdRequest.campaign_id == Campaign.campaign_id).filter(
        User.role == Role.SPONSOR,
        AdRequest.status == Status.COMPLETED,
        AdRequest.receiver_id == current_user.user_id
    ).all()
   
   # Fetch all rejected requests where receiver is an influencer
  rejected_requests = current_user.rejected_requests
        
        
  return render_template('Influencers/i_sponsor_request.html', pending_requests=pending_requests, accepted_requests=accepted_requests, rejected_requests=rejected_requests, completed_requests=completed_requests)

#Influencer Update Status
@app.route('/Influencers/update_status/<int:request_id>/<string:status>', methods=['GET'])
@influencer_required
def update_status(request_id, status):
  request = db.session.execute(db.select(AdRequest).where(AdRequest.request_id == request_id)).scalar_one_or_none()
  if request:
    if status == 'ACCEPTED':
      request.status = Status.ACCEPTED
      request.receiver_id = current_user.user_id
      db.session.commit()
    elif status == 'REJECTED':
      current_user.rejected_requests.append(request)
      db.session.commit()
  return redirect(url_for('i_sponsor_request'))

#Search Campaigns
@app.route('/Influencers/search_campaigns', methods=['GET'])
@influencer_required
def search_campaigns():
    search_term = request.args.get('search_term')
    print(f"Received search query: {search_term}")  # Debug print

    if search_term:
        try:
            # Query the database for campaigns matching the search term and are active
            results = db.session.execute(
                db.select(Campaign)
                .where(
                    (Campaign.flagged == False) &
                    (Campaign.title.ilike(f"%{search_term}%")) | 
                    (Campaign.niche.ilike(f"%{search_term}%")),
                    Campaign.status == Status.ACTIVE,
                    Campaign.visibility == Visibility.PUBLIC
                )
            ).scalars().all()
            print(f"Found {len(results)} results")  # Debug print
        except Exception as e:
            print(f"Error during database query: {e}")  # Debug print
            results = []
        
        return render_template('search_campaigns.html', results=results, search_term=search_term)
    else:
        print("No query provided, redirecting to dashboard")  # Debug print
        return redirect(url_for('influencer_dashboard'))

    
#My Requests(Influencer)
@app.route('/Influencers/My-Requests')
@influencer_required
def i_my_requests():
    # Fetch all requests where sender is the current user
    requests = db.session.execute(db.select(AdRequest).where(AdRequest.sender_id == current_user.user_id)).scalars().all()
    return render_template('Influencers/i_my_req.html', requests=requests)

#Delete My Requests
@app.route('/Influencers/delete-my-request/<int:request_id>')
@influencer_required
def i_delete_request(request_id):
    request = db.session.get(AdRequest, request_id)
    if not request:
        flash('Request not found!', 'error')
        return redirect(url_for('i_my_requests'))
    db.session.delete(request)
    db.session.commit()
    flash('Request deleted successfully!', 'success')
    return redirect(url_for('i_my_requests'))


#View Campaigns
@app.route('/Influencers/View-Campaigns')
@influencer_required
def i_view_campaigns():
    # Fetch all public campaigns and active campaigns
    public_active_campaigns = db.session.execute(db.select(Campaign).where(Campaign.status == Status.ACTIVE, Campaign.visibility == Visibility.PUBLIC)).scalars().all()
    
    # Fetch all private campaigns and active campaigns where campaign niche matches influencer niche
    private_active_campaigns = db.session.execute(
        db.select(Campaign)
        .where(
            Campaign.visibility == Visibility.PRIVATE,
            Campaign.status == Status.ACTIVE,
            (Campaign.niche == current_user.niche)|
            (Campaign.niche == 'All')
        )
    ).scalars().all()
    
    # Combine the two lists
    campaigns = private_active_campaigns + public_active_campaigns
    
    return render_template('Influencers/i_view_campaigns.html', campaigns=campaigns)

# # Influencer Rejecting Campaign
# @app.route('/Influencers/reject_campaign/<int:campaign_id>')
# @influencer_required
# def reject_campaign(campaign_id):
#     campaign = db.session.get(Campaign, campaign_id)
#     campaign.status = Status.REJECTED
#     db.session.commit()
#     flash('Campaign rejected successfully!', 'success')
#     return redirect(url_for('i_view_campaigns'))


#Delete My Requests(Influencer)
@app.route('/Influencers/delete_my_request/<int:request_id>')
@influencer_required
def delete_my_request(request_id):
    request_to_delete = db.session.get(AdRequest, request_id)
    if not request_to_delete:
        flash('Request not found!', 'error')
        return redirect(url_for('i_my_requests'))
    db.session.delete(request_to_delete)
    db.session.commit()
    flash('Request deleted successfully!', 'success')
    return redirect(url_for('i_my_requests'))

#Negotiation Page(Influencer)
@app.route('/Influencers/negotiation-page', methods=['GET'])
@influencer_required
def i_negotiation_page():
    #fetch all the requests with receiver as current user and status as SPONSOR_COUNTER
    requests = db.session.execute(db.select(AdRequest).where( AdRequest.status == Status.SPONSOR_COUNTER, AdRequest.receiver_id == current_user.user_id)).scalars().all()
    print(requests)
    return render_template('Influencers/i_negotiation.html', requests=requests)


#Negotiation Form Page(Influencer)
@app.route('/Influencers/Negotiation-Form/<int:request_id>', methods=['GET', 'POST'])
@influencer_required
def i_negotiation_form(request_id):
    data = db.session.execute(db.select(AdRequest).where(AdRequest.request_id == request_id)).scalar_one_or_none()
    if not data:
        flash('Request not found!', 'error')
        return redirect(url_for('i_sponsor_requests'))
    return render_template('Influencers/i_negotiation_form.html', data=data)

#Negotiation Form Submit(Influencer)
@app.route('/Influencers/Negotiation-Form-Submit/<int:request_id>', methods=['GET', 'POST'])
@influencer_required
def i_negotiation_form_submit(request_id):
    if request.method == 'POST':
      counter_amount = float(request.form.get('counter_amount'))
      data = db.session.execute(db.select(AdRequest).where(AdRequest.request_id == request_id)).scalar_one_or_none()
      if not data:
          flash('Request not found!', 'error')
          print('request not found')
          return redirect(url_for('i_sponsor_request'))
      data.status = Status.INFLUENCER_COUNTER
      data.amount = counter_amount
      data.receiver_id = data.sender_id
      data.sender_id = current_user.user_id
      db.session.commit()
      flash('Negotiation form submitted successfully!', 'success')
      print('negotiation offer sent')
      return redirect(url_for('i_sponsor_request'))



if __name__ == '__main__':
    app.run(debug=True)