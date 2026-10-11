import { readFileSync } from 'node:fs';
import { totalAmounts } from './totals.js';

const csv = readFileSync(new URL('../data/invoices.csv', import.meta.url), 'utf8');
const rows = csv.trim().split(/\r?\n/).slice(1);
const amounts = rows.map(row => Number(row.split(',')[2]));

console.log('Invoice Desk — fictional sample data');
console.log(`Invoices: ${rows.length}`);
console.log(`Total: USD ${totalAmounts(amounts).toFixed(2)}`);
