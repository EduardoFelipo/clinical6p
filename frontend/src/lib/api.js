import axios from "axios";

const API_BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

const api = axios.create({
  baseURL: API_BASE_URL,
  withCredentials: true,
  headers: {
    "Content-Type": "application/json",
  },
});

// Interceptor para tratar erros — cookie httpOnly é enviado automaticamente pelo browser
api.interceptors.response.use(
  (response) => response,
  (error) => {
    const isLoginRoute = error.config?.url?.includes("/login");
    const hasUser = !!localStorage.getItem("user");
    // Redireciona apenas se havia sessão ativa e não é a própria rota de login
    if (error.response?.status === 401 && hasUser && !isLoginRoute) {
      localStorage.removeItem("user");
      window.location.href = "/login";
    }
    return Promise.reject(error);
  },
);

export default api;
