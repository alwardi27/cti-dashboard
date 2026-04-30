export function parseCsvRows(text) {
    return String(text || '')
        .split(/\r?\n/)
        .map(line => line.trim())
        .filter(line => line && !line.startsWith('#'))
        .map(parseCsvLine);
}

export function parseCsvLine(line) {
    const fields = [];
    let field = '';
    let quoted = false;

    for (let index = 0; index < line.length; index++) {
        const char = line[index];
        const next = line[index + 1];

        if (char === '"' && quoted && next === '"') {
            field += '"';
            index++;
        } else if (char === '"') {
            quoted = !quoted;
        } else if (char === ',' && !quoted) {
            fields.push(field);
            field = '';
        } else {
            field += char;
        }
    }

    fields.push(field);
    return fields.map(value => value.trim());
}

