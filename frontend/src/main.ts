import { mount } from "svelte";

import App from "./App.svelte";
import "./styles.css";

// Theme follows the OS preference; the toggle applies to this tab only.
// Nothing is written to browser storage.
const dark = window.matchMedia("(prefers-color-scheme: dark)");
document.documentElement.dataset.theme = dark.matches ? "dark" : "light";

const target = document.getElementById("app");
if (target) mount(App, { target });
