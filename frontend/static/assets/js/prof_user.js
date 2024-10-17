document.getElementById('editImageButton').addEventListener('click', function() {
  document.getElementById('imageInput').click();
});

document.getElementById('imageInput').addEventListener('change', function(event) {
  const file = event.target.files[0];
  if (file) {
    const formData = new FormData();
    formData.append('picture', file);

    // Fetch the CSRF token from the cookie
    const getCookie = (name) => {
      let cookieValue = null;
      if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
          const cookie = cookies[i].trim();
          // Does this cookie string begin with the name we want?
          if (cookie.substring(0, name.length + 1) === (name + '=')) {
            cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
            break;
          }
        }
      }
      return cookieValue;
    };

    const csrfToken = getCookie('csrftoken');

    fetch('/api/upload_profile_picture/', {
      method: 'POST',
      headers: {
        'X-CSRFToken': csrfToken
      },
      body: formData
    })
    .then(response => response.json())
    .then(data => {
      if (data.success) {
        alert('Image uploaded successfully.');
        location.reload(); // Reload the page to show the updated image
      } else {
        alert('Image upload failed: ' + data.error);
      }
    })
    .catch(error => {
      console.error('Error:', error);
      alert('An error occurred during image upload. Please try again.');
    });
  }
});

document.addEventListener('click', function() {
  const alertBox = document.getElementById('alertBox');
  const success = document.getElementById('successBox');
  if (alertBox) {
    alertBox.remove();
  }
  if (success) {  
    success.remove();
  }
});

document.addEventListener('DOMContentLoaded', function () {
  // Function to set the active tab on page load
  function setActiveTab() {
    var activeTab = localStorage.getItem('activeTab');
    if (activeTab) {
      var tab = new bootstrap.Tab(document.querySelector(`button[data-bs-target="${activeTab}"]`));
      tab.show();
    }
  }

  // Set the active tab on page load
  setActiveTab();

  // Store the active tab in local storage when a tab is clicked
  var tabLinks = document.querySelectorAll('button[data-bs-toggle="tab"]');
  tabLinks.forEach(function (tabLink) {
    tabLink.addEventListener('shown.bs.tab', function (event) {
      var activeTab = event.target.getAttribute('data-bs-target');
      localStorage.setItem('activeTab', activeTab);
    });
  });
});


