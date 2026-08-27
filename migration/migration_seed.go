package migration

import (
	"fmt"

	"gorm.io/gorm"
)

// AutoMigrate runs GORM AutoMigrate and alters columns for development prototyping
func AutoMigrate(db *gorm.DB, models ...interface{}) error {
	if err := db.AutoMigrate(models...); err != nil {
		return fmt.Errorf("Automigrate failed: %w", err)
	}

	migrator := db.Migrator()
	for _, model := range models {
		stmt := &gorm.Statement{DB: db}
		if err := stmt.Parse(model); err != nil {
			return fmt.Errorf("failed to parse model %T: %w", model, err)
		}
		for _, field := range stmt.Schema.Fields {
			if field.DBName == "" || field.PrimaryKey || field.AutoCreateTime > 0 || field.AutoUpdateTime > 0 {
				continue
			}
			if err := migrator.AlterColumn(model, field.Name); err != nil {
				return fmt.Errorf("AlterColumn %s.%s failed: %w", stmt.Schema.Table, field.DBName, err)
			}
		}
	}

	return nil
}

// Migrate is an alias for AutoMigrate for backward compatibility
func Migrate(db *gorm.DB, models ...interface{}) error {
	return AutoMigrate(db, models...)
}