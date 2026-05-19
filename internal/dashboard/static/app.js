// Progressive enhancement only. Every page is fully rendered and usable
// server-side; this script enhances existing markup and never produces
// primary content. If it fails to load, nothing breaks.

// <kura-copy> wraps a command block and adds a copy-to-clipboard button.
// With JS off it is an inert wrapper around the <pre>, so the command is
// still visible and selectable.
class KuraCopy extends HTMLElement {
  connectedCallback() {
    if (!navigator.clipboard) return;
    const code = this.querySelector("code, pre");
    if (!code) return;

    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "copy-btn";
    btn.textContent = "Copy";
    btn.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(code.textContent.trim());
        btn.textContent = "Copied";
        setTimeout(() => { btn.textContent = "Copy"; }, 1500);
      } catch {
        btn.textContent = "Press ⌘C";
      }
    });
    this.appendChild(btn);
  }
}

customElements.define("kura-copy", KuraCopy);
