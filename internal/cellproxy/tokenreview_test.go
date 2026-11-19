package cellproxy

import (
	"context"
	"errors"
	"reflect"
	"testing"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	authenticationv1client "k8s.io/client-go/kubernetes/typed/authentication/v1"
)

type fakeReviews struct {
	authenticationv1client.TokenReviewExpansion
	got  *authenticationv1.TokenReview
	resp *authenticationv1.TokenReview
	err  error
}

func (f *fakeReviews) Create(_ context.Context, tr *authenticationv1.TokenReview, _ metav1.CreateOptions) (*authenticationv1.TokenReview, error) {
	f.got = tr.DeepCopy()
	return f.resp, f.err
}

func TestKubeReviewerAsksForTheAudience(t *testing.T) {
	f := &fakeReviews{resp: &authenticationv1.TokenReview{Status: authenticationv1.TokenReviewStatus{
		Authenticated: true,
		User:          authenticationv1.UserInfo{Username: subReader},
		Audiences:     []string{storeAudience},
	}}}
	got, err := (&KubeReviewer{Reviews: f}).Review(t.Context(), "tok", storeAudience)
	if err != nil {
		t.Fatal(err)
	}
	want := TokenReview{Authenticated: true, Username: subReader, Audiences: []string{storeAudience}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if f.got.Spec.Token != "tok" || !reflect.DeepEqual(f.got.Spec.Audiences, []string{storeAudience}) {
		t.Fatalf("spec %+v, want the token and the audience", f.got.Spec)
	}
}

func TestKubeReviewerRefusal(t *testing.T) {
	f := &fakeReviews{resp: &authenticationv1.TokenReview{Status: authenticationv1.TokenReviewStatus{Error: "bad audience"}}}
	got, err := (&KubeReviewer{Reviews: f}).Review(t.Context(), "tok", storeAudience)
	if err != nil || got.Authenticated || got.Error != "bad audience" {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestKubeReviewerError(t *testing.T) {
	boom := errors.New("api down")
	_, err := (&KubeReviewer{Reviews: &fakeReviews{err: boom}}).Review(t.Context(), "tok", storeAudience)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}
}
