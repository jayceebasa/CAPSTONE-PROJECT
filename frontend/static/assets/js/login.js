/*LOGIN API*/
// document.getElementById('loginForm').addEventListener('submit', function(event) {
//   event.preventDefault();

//   const username = document.getElementById('username').value;
//   const password = document.getElementById('password').value;

//   fetch('/api/token/auth/', {
//       method: 'POST',
//       headers: {
//           'Content-Type': 'application/json',
//       },
//       body: JSON.stringify({
//           username: username,
//           password: password
//       })
//   })
//   .then(response => response.json())
//   .then(data => {
//     if (data.token) {
//       window.location.href = '/home';
//     } else {
//       alert('Login failed: ' + (data.non_field_errors || 'Invalid credentials'));
//     }
//   })
//   .catch(error => {
//     console.log('Error: ' + error);
//   });
// });

/*SHOW PASSWORD*/
document.getElementById('togglePassword').addEventListener('click', function () {
  const passwordField = document.getElementById('password');
  const passwordFieldType = passwordField.getAttribute('type');
  const togglePasswordIcon = document.getElementById('togglePasswordIcon');

  if (passwordFieldType === 'password') {
    passwordField.setAttribute('type', 'text');
    togglePasswordIcon.classList.remove('bi-eye');
    togglePasswordIcon.classList.add('bi-eye-slash');
  } else {
    passwordField.setAttribute('type', 'password');
    togglePasswordIcon.classList.remove('bi-eye-slash');
    togglePasswordIcon.classList.add('bi-eye');
  }
});

