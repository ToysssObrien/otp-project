const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch({ headless: "new" });
  const page = await browser.newPage();
  
  // Go to the OTP page
  await page.goto('http://localhost:8000/otp.html');
  
  // Wait for the app to mount
  await page.waitForSelector('.lang-switcher');
  
  // Get initial language text from the eyebrow
  const initialEyebrow = await page.$eval('.brand-eyebrow', el => el.innerText);
  console.log('Initial Eyebrow (th):', initialEyebrow);
  
  // Change the select value to EN
  await page.select('select.control-select:first-of-type', 'en');
  
  // Wait a bit
  await new Promise(r => setTimeout(r, 500));
  
  // Get the new text
  const newEyebrow = await page.$eval('.brand-eyebrow', el => el.innerText);
  console.log('New Eyebrow (en):', newEyebrow);
  
  await browser.close();
})();
