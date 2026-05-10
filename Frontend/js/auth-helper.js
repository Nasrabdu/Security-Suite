// ============================================================
// Authentication Helper — Security Suite Frontend
// Include in ALL pages via <script src="js/auth-helper.js">
// ============================================================
// ⚠️  DO NOT DELETE OR MODIFY THIS FILE — it is required by
//     every page in the frontend for auth, API URL, and logout.
// ============================================================

// API URL — points to Flask backend
const API_URL = 'http://127.0.0.1:5000';

// Navigate to correct dashboard based on role
function goToDashboard() {
    const userRole = sessionStorage.getItem('user_role');
    if (userRole === 'admin') {
        window.location.href = 'Dashbord.html';
    } else {
        window.location.href = 'UserDashboard.html';
    }
}

// Display user info in header
function displayUserInfo(userOrElementId) {
    let userName = sessionStorage.getItem('user_name');
    let userRole = sessionStorage.getItem('user_role');
    let elementId = 'userNameDisplay';

    if (typeof userOrElementId === 'object' && userOrElementId !== null) {
        if (userOrElementId.userName) userName = userOrElementId.userName;
        if (userOrElementId.userRole) userRole = userOrElementId.userRole;
    } else if (typeof userOrElementId === 'string') {
        elementId = userOrElementId;
    }

    const targets = [elementId, 'userNameDisplay', 'userName'];
    for (const id of targets) {
        const element = document.getElementById(id);
        if (element && userName) {
            element.textContent = userRole ? `${userName} (${userRole})` : userName;
            break;
        }
    }
}

// Logout — clears session and redirects to sign-in
function logout() {
    sessionStorage.clear();
    window.location.href = 'signin.html';
}

// Auth guard — redirects to sign-in if no session
function checkAuth() {
    if (!sessionStorage.getItem('user_id')) {
        window.location.href = 'signin.html';
        return false;
    }
    return getUser();
}

// Get current user from sessionStorage
function getUser() {
    return {
        id:    sessionStorage.getItem('user_id'),
        email: sessionStorage.getItem('user_email'),
        name:  sessionStorage.getItem('user_name'),
        role:  sessionStorage.getItem('user_role')
    };
}
