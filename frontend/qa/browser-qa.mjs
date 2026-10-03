import { chromium } from 'playwright'
import fs from 'node:fs/promises'

const viewports = [[320, 720], [375, 812], [768, 1024], [1024, 768], [1366, 768], [1536, 864], [1920, 1080]]
const browser = await chromium.launch({ headless: true })
const output = 'qa-output'
await fs.mkdir(output, { recursive: true })
const page = await browser.newPage({ viewport: { width: 1366, height: 768 } })
await page.goto('http://localhost:5173/', { waitUntil: 'networkidle' })
await page.screenshot({ path: `${output}/scan-desktop.png`, fullPage: true })
if (!await page.getByRole('heading', { name: /Analyze a URL/ }).isVisible()) throw new Error('Scan page did not load')

await page.getByLabel('URL to analyze').fill('https://fast.com/')
await page.getByRole('button', { name: /Scan URL/ }).click()
await page.getByText('SAFE', { exact: true }).first().waitFor()
const probability = page.locator('.probability strong')
if (!await probability.isVisible() || !/^\d+\.\d+%$/.test(await probability.textContent())) throw new Error('Fast.com probability did not render')
await page.getByRole('button', { name: /Show technical analysis/ }).click()
if (!await page.getByText('URL length', { exact: true }).isVisible()) throw new Error('Technical feature grid did not render')
await page.screenshot({ path: `${output}/scan-result.png`, fullPage: true })

await page.getByLabel('URL to analyze').fill('not-a-url')
await page.getByRole('button', { name: /Scan URL/ }).click()
if (!await page.getByRole('alert').isVisible()) throw new Error('Invalid URL error did not render')

for (const suspicious of [
  'https://paypal-login.example.com/verify-account',
  'http://secure-bank-login.example.com/update-account',
  'http://microsoft-security.example.com/login',
  'http://free-iphone-winner.example.com/claim',
  'http://account-verify.example.com/signin/password',
]) {
  await page.getByLabel('URL to analyze').fill(suspicious)
  await page.getByRole('button', { name: /Scan URL/ }).click()
  await page.getByText('PHISHING', { exact: true }).first().waitFor()
}

await page.getByRole('button', { name: 'History' }).click()
await page.getByRole('heading', { name: 'Scan history' }).waitFor()
await page.screenshot({ path: `${output}/history.png`, fullPage: true })
await page.getByRole('button', { name: 'Analysis' }).click()
await page.getByRole('heading', { name: 'Analysis' }).waitFor()
await page.getByRole('button', { name: 'About' }).click()
await page.getByRole('heading', { name: 'About VIGIL' }).waitFor()

for (const [width, height] of viewports) {
  await page.setViewportSize({ width, height })
  await page.goto('http://localhost:5173/', { waitUntil: 'networkidle' })
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1)
  if (overflow) throw new Error(`Horizontal overflow at ${width}x${height}`)
  if (width <= 375) await page.screenshot({ path: `${output}/scan-${width}.png`, fullPage: true })
}

await page.emulateMedia({ reducedMotion: 'reduce' })
await page.goto('http://localhost:5173/', { waitUntil: 'networkidle' })
if (await page.locator('.risk-meter__fill').count() !== 0) throw new Error('Unexpected result on reduced-motion idle page')
console.log(JSON.stringify({ viewports, screenshots: output, scan: 'SAFE result rendered', invalid_url: 'error rendered', reduced_motion: 'emulated', overflow: 'none' }, null, 2))
await browser.close()
