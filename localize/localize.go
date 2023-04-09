package localize

import (
	"context"
	"encoding/json"

	"github.com/BurntSushi/toml"
	utils "github.com/Pharmacity-JSC/pmc-ecm-utility-golang"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/transport"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"golang.org/x/text/language"
)

type ILocalConfig interface {
	GetLocalize() string
	GetMessageFormat() string
	GetMessagePath() string
	GetMessageTag() string
}

type ILocalizeService interface {
	GetLocalizeService()
	MessageFromLocale(string, string, ...interface{}) string
	MessageFromContext(context.Context, string, ...interface{}) string
}

type localizeService struct {
	langs map[string]*i18n.Localizer
}

func NewLocalizeService(configs ...ILocalConfig) ILocalizeService {
	langs := map[string]*i18n.Localizer{}
	for _, e := range configs {
		bundle := i18n.NewBundle(language.Make(e.GetMessageTag()))
		bundle.RegisterUnmarshalFunc(e.GetMessageFormat(), utils.IIF(e.GetMessageFormat() == "json", json.Unmarshal, toml.Unmarshal))
		bundle.MustLoadMessageFile(e.GetMessagePath())
		langs[e.GetLocalize()] = i18n.NewLocalizer(bundle, e.GetLocalize())
	}
	return &localizeService{langs: langs}
}

func (s *localizeService) GetLocalizeService() {}

func (s *localizeService) MessageFromContext(ctx context.Context, msgID string, template ...interface{}) string {
	trans, ok := transport.FromServerContext(ctx)
	if !ok {
		return msgID
	}

	return s.MessageFromLocale(trans.RequestHeader().Get("Accept-Language"), msgID, template...)
}

func (s *localizeService) MessageFromLocale(locale string, msgID string, template ...interface{}) string {
	localizer, exists := s.langs[locale]
	if !exists {
		return msgID
	}

	config := &i18n.LocalizeConfig{MessageID: msgID}
	message, err := localizer.Localize(config)
	if err != nil {
		log.Error(err)
		return msgID
	}

	return utils.StringFormat(message, template...)
}
