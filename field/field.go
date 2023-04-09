package field

type IFieldsError interface {
	Error() string
	Fields() []interface{}
	Status() int
}

func NewFieldsError(err string, status int, field ...interface{}) IFieldsError {
	return &fieldsError{err: err, status: status, fields: field}
}

type fieldsError struct {
	err    string
	fields []interface{}
	status int
}

func (v *fieldsError) Error() string {
	return v.err
}

func (v *fieldsError) Fields() []interface{} {
	return v.fields
}

func (v *fieldsError) Status() int {
	return v.status
}
