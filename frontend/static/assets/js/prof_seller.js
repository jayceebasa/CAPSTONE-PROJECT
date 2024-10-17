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

var ordersTab = document.querySelector('button[data-bs-target="#order-tab-pane"]');
  if (ordersTab) {
    ordersTab.addEventListener('click', function () {
      localStorage.setItem('activeTab', '#order-tab-pane');
      window.location.href = "/seller/";
    });
  }