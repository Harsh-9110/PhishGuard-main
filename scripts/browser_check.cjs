// Requires Playwright and its Chromium binary. Tests the UI against the fixture server.
const assert=require('node:assert/strict');
const {chromium}=require('playwright');
(async()=>{
  const browser=await chromium.launch({headless:true});
  try{
    const page=await browser.newPage();
    await page.goto(process.env.PHISHGUARD_TEST_BASE||'http://127.0.0.1:5061');
    await page.locator('#url').fill('http://www.wikipedia.org/phishing');
    await page.locator('#scan-button').click();
    await page.locator('#result h2').waitFor({timeout:15000});
    assert.equal(await page.locator('#result h2').textContent(),'Potential phishing risk');
    assert.equal(await page.locator('.model').count(),3);
    assert.equal(await page.locator('.chart-row').count(),10);
    await page.getByRole('link',{name:'History',exact:true}).click();
    await page.locator('.history-item').first().waitFor();
    assert.ok(await page.locator('.history-item').count()>0);
    await page.locator('.history-item a').first().click();
    await page.locator('#result h2').waitFor();
    console.log('PASS: browser form -> fixture fetch -> real ML -> chart -> history -> saved result');
  }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
