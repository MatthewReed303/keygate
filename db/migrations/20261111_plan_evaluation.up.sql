-- Plans: evaluation plans. A product's plan with evaluation_minutes > 0
-- lets an unlicensed machine ask POST /license/evaluate for a signed
-- token of that plan, bound to its identifier and valid for that many
-- minutes. No licence row is created.
ALTER TABLE plans ADD COLUMN IF NOT EXISTS evaluation_minutes INTEGER NOT NULL DEFAULT 0;
