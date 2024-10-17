document.getElementById('registerForm').addEventListener('submit', function(event) {
  event.preventDefault();

  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  const email = document.getElementById('email').value;
  const firstName = document.getElementById('firstName').value;
  const lastName = document.getElementById('lastName').value;

  fetch('/api/register/', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': document.querySelector('[name=csrfmiddlewaretoken]').value
    },
    body: JSON.stringify({
      username: username,
      password: password,
      email: email,
      first_name: firstName,
      last_name: lastName,
      role: 'Seller',  // Add the role column with the value 'Seller'
    }),
  })
  .then(response => {
    const contentType = response.headers.get('content-type');
    if (contentType && contentType.includes('application/json')) {
      return response.json().then(data => ({ status: response.status, body: data }));
    } else {
      return response.text().then(text => ({ status: response.status, body: { error: text } }));
    }
  })
  .then(({ status, body }) => {
    const messageContainer = document.getElementById('message-container');
    messageContainer.innerHTML = '';  // Clear previous messages

    if (status === 201) {
      messageContainer.innerHTML = `
        <div class="row justify-content-center">
          <div class="col-12 col-md-8 offset-md-4">
            <div class="alert alert-success alert-dismissible fade show" role="alert">
              ${body.message}
              <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
          </div>
        </div>
      `;
      setTimeout(() => {
        window.location.href = '/login/';
      }, 2000);  // Redirect to login page after 2 seconds
    } else {
      messageContainer.innerHTML = `
        <div class="row justify-content-center">
          <div class="col-12 col-md-8 offset-md-4">
            <div class="alert alert-danger alert-dismissible fade show" role="alert">
              ${body.error || JSON.stringify(body)}
              <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
          </div>
        </div>
      `;
    }
  })
  .catch(error => {
    console.error('Error:', error);
    const messageContainer = document.getElementById('message-container');
    messageContainer.innerHTML = `
      <div class="row justify-content-center">
        <div class="col-12 col-md-8 offset-md-4">
          <div class="alert alert-danger alert-dismissible fade show" role="alert">
            An error occurred during registration. Please try again.
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
          </div>
        </div>
      </div>
    `;
  });
});

document.addEventListener('DOMContentLoaded', function () {
  const togglePassword = document.getElementById('togglePassword');
  const passwordInput = document.getElementById('password');

  togglePassword.addEventListener('click', function () {
    // Toggle the type attribute
    const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
    passwordInput.setAttribute('type', type);

    // Toggle the eye icon
    this.querySelector('i').classList.toggle('bi-eye');
    this.querySelector('i').classList.toggle('bi-eye-slash');
  });
});