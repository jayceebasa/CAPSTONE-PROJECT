document.addEventListener("DOMContentLoaded", function () {
  const ctx = document.getElementById("myChart").getContext("2d");
  const dropdownItems = document.querySelectorAll(".dropdown-item");
  const themeToggle = document.getElementById("bd-theme");
  const themeText = document.getElementById("bd-theme-text");
  const themeButtons = document.querySelectorAll("[data-bs-theme-value]");
  const dashboardLink = document.getElementById("dashboard-link");
  const ordersLink = document.getElementById("orders-link");
  const productsLink = document.getElementById("products-link");
  const sellersLink = document.getElementById("sellers-link");
  const dashboardView = document.getElementById("dashboard-view");
  const ordersView = document.getElementById("orders-view");
  const productsView = document.getElementById("products-view");
  const sellersView = document.getElementById("sellers-view");
  let myChart;

  // Function to fetch data
  async function fetchData(url) {
    const response = await fetch(url);
    if (!response.ok) throw new Error(`Failed to fetch data from ${url}`);
    return response.json();
  }

  // Function to fetch login data
  async function fetchLoginData(type) {
    return fetchData(`/api/login-data/?type=${type}`);
  }

  // Function to fetch user creation data
  async function fetchUserCreationData(type) {
    return fetchData(`/api/user-creation-data/?type=${type}`);
  }

  // Function to update the chart
  async function updateChart(type) {
    const loginData = await fetchLoginData(type);
    const userCreationData = await fetchUserCreationData(type);

    const labels = Object.keys(loginData);
    const loginCounts = Object.values(loginData);
    const userCreationCounts = labels.map((label) => userCreationData[label] || 0);

    if (myChart) {
      myChart.destroy();
    }

    const theme = localStorage.getItem("theme") || "auto";
    const chartColors =
      theme === "dark"
        ? {
            loginBackgroundColor: "rgba(255, 99, 132, 0.2)",
            loginBorderColor: "rgba(255, 99, 132, 1)",
            userCreationBackgroundColor: "rgba(54, 162, 235, 0.2)",
            userCreationBorderColor: "rgba(54, 162, 235, 1)",
          }
        : {
            loginBackgroundColor: "rgba(75, 192, 192, 0.2)",
            loginBorderColor: "rgba(75, 192, 192, 1)",
            userCreationBackgroundColor: "rgba(153, 102, 255, 0.2)",
            userCreationBorderColor: "rgba(153, 102, 255, 1)",
          };

    myChart = new Chart(ctx, {
      type: "bar",
      data: {
        labels: labels,
        datasets: [
          {
            label: "Number of Logins",
            backgroundColor: chartColors.loginBackgroundColor,
            borderColor: chartColors.loginBorderColor,
            data: loginCounts,
          },
          {
            label: "Number of User Creations",
            backgroundColor: chartColors.userCreationBackgroundColor,
            borderColor: chartColors.userCreationBorderColor,
            data: userCreationCounts,
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
              text: "Count",
            },
          },
        },
      },
    });
  }

  // Function to set the theme
  function setTheme(theme) {
    document.documentElement.setAttribute("data-bs-theme", theme);
    localStorage.setItem("theme", theme);
    themeButtons.forEach((button) => {
      button.classList.toggle("active", button.getAttribute("data-bs-theme-value") === theme);
      button.setAttribute("aria-pressed", button.getAttribute("data-bs-theme-value") === theme);
    });
    updateChart(document.querySelector(".dropdown-item.active")?.getAttribute("data-type") || "daily"); // Update the chart colors when the theme changes
  }

  // Function to fetch and display card data
  async function fetchCardData() {
    try {
      const salesTodayData = await fetchData("/api/sales-today/");
      document.getElementById("sales-today").innerText = salesTodayData.total_sales || 0;

      const totalSalesData = await fetchData("/api/total-sales/");
      document.getElementById("total-sales").innerText = totalSalesData.total_sales || 0;

      const pendingOrdersData = await fetchData("/api/pending-orders/");
      document.getElementById("pending-orders").innerText = pendingOrdersData.pending_orders || 0;
    } catch (error) {
      console.error("Error fetching card data:", error);
    }
  }

  // Function to show a specific view
  function showView(view) {
    [dashboardView, ordersView, productsView, sellersView].forEach((v) => (v.style.display = "none"));
    view.style.display = "block";
  }

  // Event listener for dropdown change
  dropdownItems.forEach((item) => {
    item.addEventListener("click", function (event) {
      const type = event.target.getAttribute("data-type");
      updateChart(type);
      document.getElementById("dropdownMenuButton").innerText = event.target.textContent; // Update dropdown text
      dropdownItems.forEach((i) => i.classList.remove("active"));
      event.target.classList.add("active");
    });
  });

  // Event listener for theme buttons
  themeButtons.forEach((button) => {
    button.addEventListener("click", () => {
      const theme = button.getAttribute("data-bs-theme-value");
      setTheme(theme);
    });
  });

  // Event listeners for sidebar links
  const sidebarLinks = [
    { link: dashboardLink, view: dashboardView },
    { link: ordersLink, view: ordersView },
    { link: productsLink, view: productsView },
    { link: sellersLink, view: sellersView },
  ];

  sidebarLinks.forEach(({ link, view }) => {
    link.addEventListener("click", function () {
      showView(view);
      sidebarLinks.forEach(({ link }) => link.classList.remove("active"));
      link.classList.add("active");
    });
  });

  // Initial chart update
  updateChart("daily");

  // Fetch and display card data
  fetchCardData();

  // Set the initial theme
  const savedTheme = localStorage.getItem("theme") || "auto";
  setTheme(savedTheme);
});
document.addEventListener("DOMContentLoaded", function () {
  const dashboardLink = document.getElementById("dashboard-link");
  const ordersLink = document.getElementById("orders-link");
  const productsLink = document.getElementById("products-link");
  const sellersLink = document.getElementById("sellers-link");

  const dashboardView = document.getElementById("dashboard-view");
  const ordersView = document.getElementById("orders-view");
  const productsView = document.getElementById("products-view");
  const sellersView = document.getElementById("sellers-view");

  function showView(view) {
    [dashboardView, ordersView, productsView, sellersView].forEach(v => v.style.display = "none");
    view.style.display = "block";
  }

  const sidebarLinks = [
    { link: dashboardLink, view: dashboardView },
    { link: ordersLink, view: ordersView },
    { link: productsLink, view: productsView },
    { link: sellersLink, view: sellersView }
  ];

  sidebarLinks.forEach(({ link, view }) => {
    link.addEventListener("click", function () {
      showView(view);
      sidebarLinks.forEach(({ link }) => link.classList.remove("active"));
      link.classList.add("active");
    });
  });

  // Initial view
  showView(dashboardView);
  dashboardLink.classList.add("active");
});
