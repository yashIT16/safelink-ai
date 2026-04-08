# 🚀 Over-The-Air (OTA) Updates Guide

Because you are hosting SafeLink AI locally and directly sharing it via GitHub (avoiding the Chrome Web Store), we have implemented a **Self-Hosted Extension Updating Protocol**. 

This means that anytime you push a change to GitHub, your users' browsers will automatically download and install the new version in the background without them doing anything!

Follow these 4 steps every time you want to release an update:

---

## 1. Increase the Version Number
Before you package your new code, you must increase the version number so Chrome knows it's a new update.
1. Open `extension/manifest.json`.
2. Change `"version": "1.0.0"` to `"version": "1.0.1"` (or whatever the next version is).
3. Open `updates.xml` in this root directory.
4. Update the `<updatecheck version='1.0.0' />` to match your new version.

---

## 2. Pack the Extension (.crx)
Chrome distributes extensions as encrypted `.crx` files. You must generate one.
1. Open Google Chrome.
2. Go to `chrome://extensions/`.
3. Enable **Developer Mode** (top right).
4. Click the **Pack extension** button.
5. For the **Extension root directory**, choose the `safelink-ai/extension/` folder.
6. For the **Private key file**:
   - **First time ever packing:** Leave this BLANK! Chrome will generate a `.pem` key file and a `extension.crx` file. **Keep that `.pem` file extremely safe**, you will need it for all future updates.
   - **Future updates:** Browse and select the `.pem` file Chrome generated for you the first time you packed it.
7. Click Pack Extension. Chrome will generate a `.crx` file right next to your `extension` folder.

---

## 3. Link Your Extension ID (First Time Only)
When you pack an extension, Chrome assigns it a permanent ID.
1. Go back to `chrome://extensions/` and drag-and-drop the generated `.crx` file into Chrome to install it as a real user.
2. Find "SafeLink AI" in your installed extensions list and copy its **ID** (e.g. `abcdefghijklmnopqrstuvwxyzaaaaaa`).
3. Open `updates.xml` and replace `YOUR_EXTENSION_ID_HERE` with your copied ID.

---

## 4. Push to GitHub!
1. Rename the generated `.crx` file to **`safelink-ai.crx`**.
2. Move it to the root of your project folder (right next to `updates.xml`).
3. Commit and push everything to GitHub!

```bash
git add .
git commit -m "Release version 1.0.1"
git push origin master
```

### Magic Complete! ✨
Every ~5 hours, Google Chrome checks `updates.xml` automatically. It will see the new version string, download `safelink-ai.crx`, and instantly upgrade all of your users to the newest version in the background!
