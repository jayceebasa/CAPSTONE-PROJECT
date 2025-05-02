document.addEventListener("DOMContentLoaded", function () {
  // Password toggle functionality
  const togglePassword = document.getElementById("togglePassword");
  const passwordInput = document.getElementById("password");

  if (togglePassword) {
    togglePassword.addEventListener("click", function () {
      // Toggle the type attribute
      const type = passwordInput.getAttribute("type") === "password" ? "text" : "password";
      passwordInput.setAttribute("type", type);

      // Toggle the eye icon
      this.querySelector("i").classList.toggle("bi-eye");
      this.querySelector("i").classList.toggle("bi-eye-slash");
    });
  }

  // Form submission with loading state
  const registerForm = document.getElementById("registerForm");
  if (registerForm) {
    registerForm.addEventListener("submit", function (event) {
      event.preventDefault();
      console.log("Form submission triggered");

      // Get the register button
      const registerButton = document.getElementById("registerButton");

      // Disable button and show loading spinner
      registerButton.disabled = true;
      const originalButtonText = registerButton.innerHTML;
      registerButton.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span> Processing...';
      console.log("Button disabled and spinner added");

      const username = document.getElementById("username").value;
      const password = document.getElementById("password").value;
      const email = document.getElementById("email").value;
      const firstName = document.getElementById("firstName").value;
      const lastName = document.getElementById("lastName").value;
      const role = document.querySelector('input[name="role"]').value; // Get the role value

      fetch("/api/register/", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": document.querySelector("[name=csrfmiddlewaretoken]").value,
        },
        body: JSON.stringify({
          username: username,
          password: password,
          email: email,
          first_name: firstName,
          last_name: lastName,
          role: role, // Include the role in the request body
        }),
      })
        .then((response) => {
          // Rest of your existing code
          const contentType = response.headers.get("content-type");
          if (contentType && contentType.includes("application/json")) {
            return response.json().then((data) => ({ status: response.status, body: data }));
          } else {
            return response.text().then((text) => ({ status: response.status, body: { error: text } }));
          }
        })
        .then(({ status, body }) => {
          const messageContainer = document.getElementById('message-container');
          messageContainer.innerHTML = '';  // Clear previous messages
        
          if (status === 201) {
            messageContainer.innerHTML = `
              <div class="alert alert-success alert-dismissible fade show" role="alert">
                ${body.message}
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
              </div>
            `;
            setTimeout(() => {
              window.location.href = '/login/';
            }, 2000);  // Redirect to login page after 2 seconds
          } else {
            messageContainer.innerHTML = `
              <div class="alert alert-danger alert-dismissible fade show" role="alert">
                ${body.error || JSON.stringify(body)}
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
              </div>
            `;
            
            // Re-enable the button on error
            registerButton.disabled = false;
            registerButton.innerHTML = originalButtonText;
          }
        })
        .catch(error => {
          console.error('Error:', error);
          const messageContainer = document.getElementById('message-container');
          messageContainer.innerHTML = `
            <div class="alert alert-danger alert-dismissible fade show" role="alert">
              An error occurred during registration. Please try again.
              <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
          `;
          
          // Re-enable the button on error
          registerButton.disabled = false;
          registerButton.innerHTML = originalButtonText;
        });
    });
  }
});
