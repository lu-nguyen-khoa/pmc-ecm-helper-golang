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
	GetMessage(ctx context.Context, msgID string, template ...interface{}) string
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

func (s *localizeService) FindLang(context context.Context) string {
	ctx, ok := transport.FromServerContext(context)
	if !ok {
		return "vi"
	}

	lang := ctx.RequestHeader().Get("accept-language")
	return lang
}

func (s *localizeService) FindLocalize(context context.Context) *i18n.Localizer {
	lang := s.FindLang(context)
	result, exists := s.langs[lang]
	if !exists {
		return nil
	}

	return result
}

func (s *localizeService) GetMessage(ctx context.Context, msgID string, template ...interface{}) string {
	localizer := s.FindLocalize(ctx)
	if localizer == nil {
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
