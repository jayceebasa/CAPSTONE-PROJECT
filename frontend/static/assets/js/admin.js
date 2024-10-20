document.addEventListener("DOMContentLoaded", function () {
  const ctx = document.getElementById("myChart").getContext("2d");
  const dropdownItems = document.querySelectorAll(".dropdown-item");
  const themeToggle = document.getElementById('bd-theme');
  const themeText = document.getElementById('bd-theme-text');
  const themeButtons = document.querySelectorAll('[data-bs-theme-value]');
  let myChart;

  // Function to fetch login data
  async function fetchLoginData(type) {
    const response = await fetch(`/api/login-data/?type=${type}`);
    const data = await response.json();
    return data;
  }

  // Function to update the chart
  async function updateChart(type) {
    const loginData = await fetchLoginData(type);
    const labels = Object.keys(loginData);
    const data = Object.values(loginData);

    if (myChart) {
      myChart.destroy();
    }

    const theme = localStorage.getItem('theme') || 'auto';
    const chartColors = theme === 'dark' ? {
      backgroundColor: "rgba(255, 99, 132, 0.2)",
      borderColor: "rgba(255, 99, 132, 1)"
    } : {
      backgroundColor: "rgba(75, 192, 192, 0.2)",
      borderColor: "rgba(75, 192, 192, 1)"
    };

    myChart = new Chart(ctx, {
      type: "bar",
      data: {
        labels: labels,
        datasets: [
          {
            label: "Number of Logins",
            backgroundColor: chartColors.backgroundColor,
            borderColor: chartColors.borderColor,
            data: data,
          },
        ],
      },
      options: {
        responsive: true,
        scales: {
          x: {
            display: true,
            title: {
              display: true,
              text: "Date",
            },
          },
          y: {
            display: true,
            title: {
              display: true,
              text: "Number of Logins",
            },
          },
        },
      },
    });
  }

  // Function to set the theme
  function setTheme(theme) {
    document.documentElement.setAttribute('data-bs-theme', theme);
    localStorage.setItem('theme', theme);
    themeButtons.forEach(button => {
      button.classList.toggle('active', button.getAttribute('data-bs-theme-value') === theme);
      button.setAttribute('aria-pressed', button.getAttribute('data-bs-theme-value') === theme);
    });
    updateChart('daily'); // Update the chart colors when the theme changes
  }

  // Function to fetch and display card data
  async function fetchCardData() {
    try {
      const salesTodayResponse = await fetch("/api/sales-today/");
      if (!salesTodayResponse.ok) throw new Error('Failed to fetch sales today data');
      const salesTodayData = await salesTodayResponse.json();
      document.getElementById("sales-today").innerText = salesTodayData.total_sales || 0;

      const totalSalesResponse = await fetch("/api/total-sales/");
      if (!totalSalesResponse.ok) throw new Error('Failed to fetch total sales data');
      const totalSalesData = await totalSalesResponse.json();
      document.getElementById("total-sales").innerText = totalSalesData.total_sales || 0;

      const pendingOrdersResponse = await fetch("/api/pending-orders/");
      if (!pendingOrdersResponse.ok) throw new Error('Failed to fetch pending orders data');
      const pendingOrdersData = await pendingOrdersResponse.json();
      document.getElementById("pending-orders").innerText = pendingOrdersData.pending_orders || 0;
    } catch (error) {
      console.error('Error fetching card data:', error);
    }
  }

  // Event listener for dropdown change
  dropdownItems.forEach((item) => {
    item.addEventListener('click', function (event) {
      const type = event.target.getAttribute('data-type');
      updateChart(type);
    });
  });

  // Event listener for theme buttons
  themeButtons.forEach(button => {
    button.addEventListener('click', () => {
      const theme = button.getAttribute('data-bs-theme-value');
      setTheme(theme);
    });
  });

  // Initial chart update
  updateChart("daily");

  // Fetch and display card data
  fetchCardData();

  // Set the initial theme
  const savedTheme = localStorage.getItem('theme') || 'auto';
  setTheme(savedTheme);
});