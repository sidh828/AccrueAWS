import { Gift, Layers3 } from 'lucide-react';
import { asPercent, CATEGORIES, money } from '../format.js';

export default function CategoryBreakdown({ summary, limits }) {
  const categoryTotals = new Map();
  for (const event of summary.allowed) {
    categoryTotals.set(event.category, (categoryTotals.get(event.category) || 0) + event.amount_cents);
  }
  const categories = [...categoryTotals].sort((a,b) => b[1]-a[1]);
  return (
    <section className="panel categories">
      <div className="section-header">
        <div><div className="section-icon blue-icon"><Layers3 size={17}/></div><h3>Spending by category</h3></div>
      </div>
      <div className="gift-meter">
        <div className="category-row"><span><Gift size={17}/> Gift cards</span><strong>{money(summary.giftCardSpent)} <span>/ {money(limits.gift_card_day)}</span></strong></div>
        <div className="mini-track"><div style={{width: `${asPercent(summary.giftCardSpent, limits.gift_card_day)}%`}}/></div>
        <p>Standard gift card allowance</p>
      </div>
      {categories.filter(([name]) => name !== 'gift_card').length === 0 && <p className="muted small">No other spending recorded today.</p>}
      {categories.filter(([name]) => name !== 'gift_card').map(([name, cents]) => (
        <div key={name} className="category-other"><span>{CATEGORIES[name] || name.replaceAll('_', ' ')}</span><strong>{money(cents)}</strong></div>
      ))}
    </section>
  );
}
