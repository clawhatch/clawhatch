import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { LandingPage } from "@/components/landing/page";
import { WorldPage } from "@/routes/world";
import "@/styles.css";

const path = window.location.pathname.replace(/\/+$/, "") || "/";
const page = path === "/world" ? <WorldPage /> : <LandingPage />;

createRoot(document.getElementById("root")!).render(
  <StrictMode>{page}</StrictMode>,
);
