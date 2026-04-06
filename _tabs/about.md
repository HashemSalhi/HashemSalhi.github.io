---
# the default layout is 'page'
icon: fas fa-info-circle
order: 5
---

<style>
.section-heading {
  display: flex;
  align-items: center;
  gap: 0.6rem;
  font-size: 1.05rem;
  font-weight: 700;
  margin: 2rem 0 1.1rem 0;
}
.section-heading i { color: var(--link-color); font-size: 0.95rem; }
.section-heading::after {
  content: '';
  flex: 1;
  height: 1px;
  background: var(--card-border-color, rgba(134,140,151,0.2));
  margin-left: 0.5rem;
}
.cert-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: 1rem;
}
.cert-card {
  border: 1px solid var(--card-border-color, rgba(134,140,151,0.18));
  border-radius: 0.65rem;
  overflow: hidden;
  display: flex;
  flex-direction: column;
  background: var(--card-bg, var(--main-bg));
  transition: transform 0.2s ease, box-shadow 0.2s ease, border-color 0.2s ease;
}
.cert-card:hover {
  transform: translateY(-3px);
  box-shadow: 0 8px 22px rgba(0,0,0,0.13);
  border-color: var(--link-color);
}
.cert-preview {
  display: block;
  position: relative;
  width: 100%;
  aspect-ratio: 600 / 464;
  overflow: hidden;
  text-decoration: none !important;
  background: rgba(134,140,151,0.07);
}
.cert-preview-img {
  position: absolute;
  inset: 0;
  background-size: cover;
  background-position: top center;
  background-repeat: no-repeat;
  transition: transform 0.3s ease;
}
.cert-card:hover .cert-preview-img { transform: scale(1.04); }
.cert-overlay {
  position: absolute;
  inset: 0;
  background: rgba(0,0,0,0.4);
  display: flex;
  align-items: center;
  justify-content: center;
  opacity: 0;
  transition: opacity 0.2s;
}
.cert-card:hover .cert-overlay { opacity: 1; }
.cert-overlay span {
  font-size: 0.78rem;
  font-weight: 600;
  color: #fff;
  background: rgba(0,0,0,0.55);
  border: 1px solid rgba(255,255,255,0.3);
  padding: 0.35rem 0.85rem;
  border-radius: 2rem;
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  backdrop-filter: blur(4px);
}
.cert-footer {
  padding: 0.65rem 0.85rem;
  border-top: 1px solid var(--card-border-color, rgba(134,140,151,0.15));
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 0.5rem;
}
.cert-name {
  font-size: 0.88rem;
  font-weight: 700;
  color: var(--heading-color, inherit);
  text-decoration: none;
  line-height: 1.2;
  display: block;
}
.cert-name:hover { text-decoration: underline; color: var(--link-color); }
.cert-issuer {
  font-size: 0.68rem;
  color: var(--text-muted, #868c97);
  margin-top: 0.1rem;
}
@media (max-width: 480px) { .cert-grid { grid-template-columns: 1fr; } }
</style>

<div class="section-heading"><i class="fas fa-certificate"></i> Certifications</div>
<div class="cert-grid">
<div class="cert-card"><a class="cert-preview" href="https://www.credly.com/badges/ac5b88a1-7238-4682-b56d-3cb65f438fef/public_url" target="_blank" rel="noopener" aria-label="View CCDL2 certificate"><div class="cert-preview-img" style="background-image: url('/assets/img/certs/CCDL2.png')"></div><div class="cert-overlay"><span><i class="fas fa-external-link-alt"></i> View Certificate</span></div></a><div class="cert-footer"><div><a class="cert-name" href="https://www.credly.com/badges/ac5b88a1-7238-4682-b56d-3cb65f438fef/public_url" target="_blank" rel="noopener">CCDL2</a><div class="cert-issuer">CyberDefenders</div></div></div></div>
<div class="cert-card"><a class="cert-preview" href="https://certs.ine.com/04d7c750-2621-4dd9-a7da-49e6ad5d3576" target="_blank" rel="noopener" aria-label="View eCIR certificate"><div class="cert-preview-img" style="background-image: url('/assets/img/certs/eCIR.png')"></div><div class="cert-overlay"><span><i class="fas fa-external-link-alt"></i> View Certificate</span></div></a><div class="cert-footer"><div><a class="cert-name" href="https://certs.ine.com/04d7c750-2621-4dd9-a7da-49e6ad5d3576" target="_blank" rel="noopener">eCIR</a><div class="cert-issuer">INE Security</div></div></div></div>
<div class="cert-card"><a class="cert-preview" href="https://certs.ine.com/69c38171-31cb-47a8-80cf-00b9abed1b18" target="_blank" rel="noopener" aria-label="View eCTHP certificate"><div class="cert-preview-img" style="background-image: url('/assets/img/certs/eCTHP.png')"></div><div class="cert-overlay"><span><i class="fas fa-external-link-alt"></i> View Certificate</span></div></a><div class="cert-footer"><div><a class="cert-name" href="https://certs.ine.com/69c38171-31cb-47a8-80cf-00b9abed1b18" target="_blank" rel="noopener">eCTHP</a><div class="cert-issuer">INE Security</div></div></div></div>
<div class="cert-card"><a class="cert-preview" href="https://www.credential.net/b26d244a-ae9a-47fc-bbf1-06f86bdac127" target="_blank" rel="noopener" aria-label="View CRTP certificate"><div class="cert-preview-img" style="background-image: url('/assets/img/certs/CRTP.png')"></div><div class="cert-overlay"><span><i class="fas fa-external-link-alt"></i> View Certificate</span></div></a><div class="cert-footer"><div><a class="cert-name" href="https://www.credential.net/b26d244a-ae9a-47fc-bbf1-06f86bdac127" target="_blank" rel="noopener">CRTP</a><div class="cert-issuer">Altered Security</div></div></div></div>
<div class="cert-card"><a class="cert-preview" href="https://www.credential.net/3a82f4b5-4d53-40eb-8264-0314a8a6cfcd" target="_blank" rel="noopener" aria-label="View eJPT certificate"><div class="cert-preview-img" style="background-image: url('/assets/img/certs/eJPT.png')"></div><div class="cert-overlay"><span><i class="fas fa-external-link-alt"></i> View Certificate</span></div></a><div class="cert-footer"><div><a class="cert-name" href="https://www.credential.net/3a82f4b5-4d53-40eb-8264-0314a8a6cfcd" target="_blank" rel="noopener">eJPT</a><div class="cert-issuer">INE Security</div></div></div></div>
</div>
