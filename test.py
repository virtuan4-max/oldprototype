
#imports
import streamlit as st
import pandas as pd
import hashlib
import gspread
import os
from datetime import datetime
from oauth2client.service_account import ServiceAccountCredentials
import json
import streamlit.components.v1 as components
import re

# Streamlit App UI
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = "guest"
if "page" not in st.session_state:
    st.session_state.page = "home"

# Globals and Secrets
G_SHEET_NAME = "aixient-users"
ADMIN_USERNAME = "admin_aixient"

tags = ['AI', 'design', 'art', 'free', 'education', 'coding', 'gaming', 'tools']
websites = []
website_descriptions = []
website_freeness = []
website_tags = []

st.set_page_config(page_title="Aixient Prototype", layout="wide")

# Authentication and Database Functions
@st.cache_resource
def get_db():
    try:
        scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]
        credentials = ServiceAccountCredentials.from_json_keyfile_dict(st.secrets["gcp_service_account"], scope)
        client = gspread.authorize(credentials)
        sheet = client.open(G_SHEET_NAME).get_worksheet(0)
        return sheet
    except Exception as e:
        st.error(f"Error connecting to Google Sheets: {e}")
        return None

@st.cache_data(ttl=600)
def get_dataframe(_sheet):
    try:
        data = _sheet.get_all_records()
        df = pd.DataFrame(data)
        return df
    except Exception as e:
        st.error(f"Error reading from Google Sheets: {e}")
        return pd.DataFrame()

def update_sheet_and_clear_cache(df, sheet):
    df_string = df.astype(str)
    data_to_write = [df_string.columns.values.tolist()] + df_string.values.tolist()
    sheet.update(data_to_write)
    st.cache_data.clear()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def check_password(password, hashed_password):
    return hash_password(password) == hashed_password

def add_user(username, password):
    sheet = get_db()
    if sheet is None: return False, "Database connection failed."
    df = get_dataframe(sheet)
    if username in df.get("username", []).values:
        return False, "Username already exists."

    new_user = pd.DataFrame([{
        "username": username,
        "hashed_password": hash_password(password),
        "uploaded_websites": "",
        "description": "",
        "freeness": "",
        "tags": "",
        "uploaded_datetime": "",
        "status": "",
        "views": "",
    }])
    df = pd.concat([df, new_user], ignore_index=True)
    update_sheet_and_clear_cache(df, sheet)
    return True, "Account created successfully!"

def verify_user(username, password):
    sheet = get_db()
    if sheet is None: return False
    df = get_dataframe(sheet)
    user_data = df[df["username"] == username]
    if not user_data.empty:
        hashed_password = user_data["hashed_password"].values[0]
        return check_password(password, hashed_password)
    return False

def add_website(current_user, new_link, description, freeness, tags):
    sheet = get_db()
    if sheet is None: return False, "Database connection failed."
    df = get_dataframe(sheet)
    if current_user not in df["username"].values: return False, "User not found."
    user_index = df[df["username"] == current_user].index[0]

    uploaded_websites_list = str(df.loc[user_index, 'uploaded_websites']).split(',') if pd.notna(df.loc[user_index, 'uploaded_websites']) else []
    description_list = str(df.loc[user_index, 'description']).split(',') if pd.notna(df.loc[user_index, 'description']) else []
    freeness_list = str(df.loc[user_index, 'freeness']).split(',') if pd.notna(df.loc[user_index, 'freeness']) else []
    tags_list_of_lists = json.loads(str(df.loc[user_index, 'tags'])) if pd.notna(df.loc[user_index, 'tags']) else []
    datetime_list = str(df.loc[user_index, 'uploaded_datetime']).split(',') if pd.notna(df.loc[user_index, 'uploaded_datetime']) else []
    status_list = str(df.loc[user_index, 'status']).split(',') if pd.notna(df.loc[user_index, 'status']) else []
    views_list = str(df.loc[user_index, 'views']).split(',') if pd.notna(df.loc[user_index, 'views']) else []

    if new_link in uploaded_websites_list:
        return False, "Website already exists in your list."

    uploaded_websites_list.append(new_link)
    description_list.append(description)
    freeness_list.append(freeness)
    tags_list_of_lists.append(tags)
    current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    datetime_list.append(current_datetime)
    status_list.append("pending")
    views_list.append("0")

    df.loc[user_index, 'uploaded_websites'] = ','.join(uploaded_websites_list)
    df.loc[user_index, 'description'] = ','.join(description_list)
    df.loc[user_index, 'freeness'] = ','.join(freeness_list)
    df.loc[user_index, 'tags'] = json.dumps(tags_list_of_lists)
    df.loc[user_index, 'uploaded_datetime'] = ','.join(datetime_list)
    df.loc[user_index, 'status'] = ','.join(status_list)
    df.loc[user_index, 'views'] = ','.join(views_list)

    update_sheet_and_clear_cache(df, sheet)
    return True, "Website added successfully! Pending review."

def delete_website(current_user, link_to_delete):
    sheet = get_db()
    if sheet is None: return False, "Database connection failed."
    df = get_dataframe(sheet)
    user_index = df[df["username"] == current_user].index[0]
    
    uploaded_websites_list = str(df.loc[user_index, 'uploaded_websites']).split(',')
    description_list = str(df.loc[user_index, 'description']).split(',')
    freeness_list = str(df.loc[user_index, 'freeness']).split(',')
    tags_list = json.loads(str(df.loc[user_index, 'tags']))
    datetime_list = str(df.loc[user_index, 'uploaded_datetime']).split(',')
    views_list = str(df.loc[user_index, 'views']).split(',')
    status_list = str(df.loc[user_index, 'status']).split(',')

    if link_to_delete in uploaded_websites_list:
        link_index = uploaded_websites_list.index(link_to_delete)
        uploaded_websites_list.pop(link_index)
        description_list.pop(link_index)
        freeness_list.pop(link_index)
        tags_list.pop(link_index)
        datetime_list.pop(link_index)
        views_list.pop(link_index)
        status_list.pop(link_index)

        df.loc[user_index, 'uploaded_websites'] = ','.join(uploaded_websites_list)
        df.loc[user_index, 'description'] = ','.join(description_list)
        df.loc[user_index, 'freeness'] = ','.join(freeness_list)
        df.loc[user_index, 'tags'] = json.dumps(tags_list)
        df.loc[user_index, 'uploaded_datetime'] = ','.join(datetime_list)
        df.loc[user_index, 'views'] = ','.join(views_list)
        df.loc[user_index, 'status'] = ','.join(status_list)

        update_sheet_and_clear_cache(df, sheet)
        return True, "Website deleted successfully!"
    return False, "Website not found in your list."

# Main App Logic
sheet = get_db()
df = get_dataframe(sheet)

st.title("Aixient Prototype")

# Sidebar
with st.sidebar:
    st.header("Navigation")
    if not st.session_state.logged_in:
        if st.button("Sign in"): st.session_state.page = "Sign in"
    else:
        st.write(f"Logged in as: {st.session_state.username}")
        if st.button("Profile"): st.session_state.page = "profile"
        if st.session_state.username == ADMIN_USERNAME:
            if st.button("Admin Panel"): st.session_state.page = "admin_panel"
    if st.button("Home"): st.session_state.page = "home"
    if st.button("Recent"): st.session_state.page = "recent"

# Page Content
if st.session_state.page == "home":
    st.subheader("Discover AI Websites")
    search_query = st.text_input("Search for websites...", "")
    
    # Simple, ugly display of all websites
    for index, row in df.iterrows():
        websites_str = str(row.get('uploaded_websites', ''))
        if websites_str:
            links = websites_str.split(',')
            for link in links:
                if search_query.lower() in link.lower() or not search_query:
                    st.write(f"Link: [{link}](https://{link})")

elif st.session_state.page == "Sign in":
    st.subheader("Sign In")
    username = st.text_input("Username:")
    password = st.text_input("Password:", type="password")
    if st.button("Log In"):
        if verify_user(username, password):
            st.session_state.logged_in = True
            st.session_state.username = username
            st.success("Logged in successfully!")
            st.rerun()
        else:
            st.error("Invalid username or password.")
    st.subheader("Create Account")
    new_username = st.text_input("New Username:")
    new_password = st.text_input("New Password:", type="password")
    if st.button("Create"):
        success, message = add_user(new_username, new_password)
        if success:
            st.success(message)
        else:
            st.error(message)

elif st.session_state.page == "profile":
    st.subheader(f"Welcome, {st.session_state.username}")
    st.markdown("---")
    
    st.subheader("Add a New Website")
    with st.form("add_website_form"):
        new_link = st.text_input("Website URL:")
        description = st.text_area("Description:")
        freeness = st.radio("Freeness:", ["Completely free.", "Has a free tier."])
        tags_selected = st.multiselect("Select Tags:", options=tags)
        
        submitted = st.form_submit_button("Submit Website")
        if submitted:
            if new_link and description and freeness and tags_selected:
                success, message = add_website(st.session_state.username, new_link, description, freeness, tags_selected)
                if success:
                    st.success(message)
                else:
                    st.error(message)
            else:
                st.warning("Please fill in all fields.")

    st.markdown("---")
    st.subheader("Your Submitted Websites")
    user_data = df[df["username"] == st.session_state.username]
    if not user_data.empty:
        links_str = user_data["uploaded_websites"].values[0]
        if links_str:
            links = links_str.split(',')
            for link in links:
                st.write(f"- {link}")
                if st.button(f"Delete {link}", key=f"del_{link}"):
                    success, message = delete_website(st.session_state.username, link)
                    if success:
                        st.success(message)
                        st.rerun()
                    else:
                        st.error(message)

elif st.session_state.page == "admin_panel":
    if st.session_state.username != ADMIN_USERNAME:
        st.error("Access Denied.")
    else:
        st.subheader("Admin Panel")
        st.write("Review pending website submissions.")
        
        # Admin website review logic (simplified)
        for index, row in df.iterrows():
            if str(row.get('status', '')) == 'pending':
                st.write(f"Website from {row['username']}: {row['uploaded_websites']}")
                if st.button(f"Approve {row['uploaded_websites']}", key=f"app_{index}"):
                    st.success("Website approved.")
                if st.button(f"Reject {row['uploaded_websites']}", key=f"rej_{index}"):
                    st.error("Website rejected.")

elif st.session_state.page == "recent":
    st.subheader("Recent Submissions")
    # Fetch and display recent websites (simplified)
    # The full version's sorting logic is complex; this is a basic display.
    for index, row in df.iterrows():
        links_str = str(row.get('uploaded_websites', ''))
        if links_str:
            links = links_str.split(',')
            for link in links:
                st.write(f"- {link}")
